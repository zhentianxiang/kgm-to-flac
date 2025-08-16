// backend/main.go
package main

import (
	"archive/zip"
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"html/template"
	"io"
	"log"
	"mime/multipart"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	common "unlock-music.dev/cli/algo/common"
	"unlock-music.dev/cli/algo/kgm"
)

const (
	// 单文件最大 1 GiB
	maxFileSize = 1 << 30
	// 最大允许上传文件数
	maxFiles = 50
	// ParseMultipartForm 的内存阈值（小于该值放在内存，超过会写到临时文件）
	parseFormMemory = 32 << 20 // 32 MiB
)

// 你原来的页面（仅保留作对比/测试 - 实际前端由 nginx 提供静态文件）
const page = `<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<title>KGM → FLAC（纯Go解密）</title>
</head>
<body>
  <h1>KGM → FLAC（后端测试页面）</h1>
  <form action="/api/convert" method="post" enctype="multipart/form-data">
    <input type="file" name="files" multiple accept=".kgm,.kgma,.vpr" />
    <button type="submit">上传并转换</button>
  </form>
</body>
</html>`

func main() {
	mux := http.NewServeMux()

	// 保留一个简单的根页面（用于后端健康检查）
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		t := template.Must(template.New("index").Parse(page))
		_ = t.Execute(w, nil)
	})

	// API：批量上传
	mux.HandleFunc("/api/convert", handleConvert)

	addr := envOr("ADDR", ":8080")
	log.Printf("backend listening on %s", addr)
	if err := http.ListenAndServe(addr, logRequest(mux)); err != nil {
		log.Fatal(err)
	}
}

// logRequest 中间件记录请求基础信息、耗时等
func logRequest(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		next.ServeHTTP(w, r)
		clientIP := getClientIP(r)
		log.Printf("[REQ] %s %s ip=%s ua=%q took=%s",
			r.Method, r.URL.Path, clientIP, r.UserAgent(), time.Since(start))
	})
}

// getClientIP 尝试从 X-Forwarded-For, X-Real-IP 获取真实客户端 IP，否则返回 RemoteAddr
func getClientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		parts := strings.Split(xff, ",")
		if len(parts) > 0 {
			return strings.TrimSpace(parts[0])
		}
	}
	if xr := r.Header.Get("X-Real-Ip"); xr != "" {
		return strings.TrimSpace(xr)
	}
	// strip port if present
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func handleConvert(w http.ResponseWriter, r *http.Request) {
	startReq := time.Now()
	clientIP := getClientIP(r)
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// 限制整个请求体最大值：最多 maxFiles * maxFileSize + 小量缓冲（以字节计）
	limit := int64(maxFiles)*int64(maxFileSize) + (10 << 20) // +10MiB
	r.Body = http.MaxBytesReader(w, r.Body, limit)

	// ParseMultipartForm（会将大文件写入临时文件）
	if err := r.ParseMultipartForm(parseFormMemory); err != nil {
		http.Error(w, "表单解析失败: "+err.Error(), http.StatusBadRequest)
		log.Printf("[ERR] parse multipart form failed ip=%s err=%v", clientIP, err)
		return
	}
	defer func() {
		// 清理 ParseMultipartForm 创建的临时文件
		if r.MultipartForm != nil {
			_ = r.MultipartForm.RemoveAll()
		}
	}()

	files := r.MultipartForm.File["files"]
	if len(files) == 0 {
		http.Error(w, "未选择文件（字段名为 files）", http.StatusBadRequest)
		return
	}
	if len(files) > maxFiles {
		http.Error(w, fmt.Sprintf("最多上传 %d 个文件", maxFiles), http.StatusBadRequest)
		return
	}

	log.Printf("[UPLOAD START] ip=%s files=%d", clientIP, len(files))

	// 创建临时工作目录用于存放中间文件
	workDir, err := os.MkdirTemp("", "kgm2flac_*")
	if err != nil {
		http.Error(w, "无法创建临时工作目录: "+err.Error(), http.StatusInternalServerError)
		log.Printf("[ERR] mkdir temp failed ip=%s err=%v", clientIP, err)
		return
	}
	// 确保最后清理
	defer func() {
		_ = os.RemoveAll(workDir)
	}()

	// 记录每个文件的结果文件路径（FLAC）或错误
	type result struct {
		origName string
		outPath  string // 本地路径
		err      error
		size     int64
		duration time.Duration
	}
	results := make([]result, 0, len(files))

	// 遍历并处理每个文件（顺序处理，避免并发占用过多资源）
	for _, fh := range files {
		start := time.Now()
		log.Printf("[FILE] ip=%s filename=%s size=%d header=%v", clientIP, fh.Filename, fh.Size, fh.Header)
		if fh.Size > maxFileSize {
			err := fmt.Errorf("文件 %s 超过单文件 1GB 限制", fh.Filename)
			log.Printf("[ERR] %v", err)
			results = append(results, result{origName: fh.Filename, err: err, size: fh.Size})
			continue
		}

		// 打开上传的文件（可能已经是临时文件）
		f, err := fh.Open()
		if err != nil {
			log.Printf("[ERR] open uploaded file failed ip=%s name=%s err=%v", clientIP, fh.Filename, err)
			results = append(results, result{origName: fh.Filename, err: err, size: fh.Size})
			continue
		}

		// persistUpload 会把上传内容写到临时文件并返回路径
		inPath, cleanupIn, err := persistUpload(f, fh)
		_ = f.Close()
		if err != nil {
			log.Printf("[ERR] persist upload failed ip=%s name=%s err=%v", clientIP, fh.Filename, err)
			results = append(results, result{origName: fh.Filename, err: err, size: fh.Size})
			continue
		}
		// 确保单个输入临时文件在处理结束后移除
		defer cleanupIn()

		// 解密到原始音频流文件（可能是 .flac/.mp3/.ogg/... 二进制文件）
		outRaw, cleanupRaw, err := decryptKgmPureGo(inPath)
		if err != nil {
			log.Printf("[ERR] decrypt failed ip=%s name=%s err=%v", clientIP, fh.Filename, err)
			// 清理并继续下一个
			_ = os.Remove(inPath)
			results = append(results, result{origName: fh.Filename, err: err, size: fh.Size})
			continue
		}
		// 解密出的 raw 文件在后续也需要清理
		defer cleanupRaw()

		// 嗅探解密后格式
		rawExt, err := sniffAudioExt(outRaw)
		if err != nil {
			log.Printf("[ERR] sniff audio ext failed ip=%s name=%s err=%v", clientIP, fh.Filename, err)
			results = append(results, result{origName: fh.Filename, err: err, size: fh.Size})
			continue
		}

		var finalPath string
		if rawExt == ".flac" {
			// 如果已经是 flac，则直接重命名到工作目录以便打包
			finalPath = filepath.Join(workDir, replaceExt(fh.Filename, ".flac"))
			if err := os.Rename(outRaw, finalPath); err != nil {
				// 如果 rename 失败，尝试复制
				if err := copyFile(outRaw, finalPath); err != nil {
					log.Printf("[ERR] move/copy flac failed ip=%s name=%s err=%v", clientIP, fh.Filename, err)
					results = append(results, result{origName: fh.Filename, err: err, size: fh.Size})
					continue
				}
				_ = os.Remove(outRaw)
			}
		} else {
			// 需要 ffmpeg 转码为 flac
			ffmpeg := envOr("FFMPEG_BIN", "ffmpeg")
			finalPath = filepath.Join(workDir, replaceExt(fh.Filename, ".flac"))
			// 转码：-map_metadata -1 删除元数据以避免隐私泄露
			cmd := exec.CommandContext(r.Context(), ffmpeg, "-y", "-hide_banner", "-loglevel", "error", "-i", outRaw, "-map_metadata", "-1", finalPath)
			if err := cmd.Run(); err != nil {
				log.Printf("[ERR] ffmpeg convert failed ip=%s name=%s err=%v", clientIP, fh.Filename, err)
				results = append(results, result{origName: fh.Filename, err: fmt.Errorf("转码为 FLAC 失败: %w", err), size: fh.Size})
				continue
			}
			// 转码成功后可以删除 outRaw
			_ = os.Remove(outRaw)
		}

		dur := time.Since(start)
		log.Printf("[FILE DONE] ip=%s name=%s out=%s dur=%s", clientIP, fh.Filename, finalPath, dur)
		results = append(results, result{origName: fh.Filename, outPath: finalPath, err: nil, size: fh.Size, duration: dur})
	}

	// 统计成功数量
	successCount := 0
	for _, r := range results {
		if r.err == nil {
			successCount++
		}
	}

	// 如果只有一个成功文件，则直接返回该 FLAC 文件（attachment）
	if successCount == 1 {
		var fileToServe string
		var origName string
		for _, rr := range results {
			if rr.err == nil {
				fileToServe = rr.outPath
				origName = rr.origName
				break
			}
		}
		if fileToServe == "" {
			http.Error(w, "内部错误：没有可下载的文件", http.StatusInternalServerError)
			return
		}
		// 记录日志：返回文件
		log.Printf("[RESP] ip=%s serve single file=%s size=%d", clientIP, fileToServe, fileSizeSafe(fileToServe))
		w.Header().Set("Content-Type", "audio/flac")
		w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", replaceExt(origName, ".flac")))
		http.ServeFile(w, r, fileToServe)
		return
	}

	// 多个成功文件：打包 zip 并返回
	zipPath := filepath.Join(workDir, "kgm2flac_result_"+randHex(8)+".zip")
	zipFile, err := os.Create(zipPath)
	if err != nil {
		http.Error(w, "无法创建 zip 文件: "+err.Error(), http.StatusInternalServerError)
		log.Printf("[ERR] create zip failed ip=%s err=%v", clientIP, err)
		return
	}
	zw := zip.NewWriter(zipFile)
	// 将每个成功的 outPath 写入 zip
	for _, rr := range results {
		if rr.err != nil || rr.outPath == "" {
			continue
		}
		if err := addFileToZip(zw, rr.outPath, filepath.Base(rr.outPath)); err != nil {
			log.Printf("[ERR] add to zip failed ip=%s file=%s err=%v", clientIP, rr.outPath, err)
		}
	}
	if err := zw.Close(); err != nil {
		_ = zipFile.Close()
		http.Error(w, "无法生成 zip: "+err.Error(), http.StatusInternalServerError)
		log.Printf("[ERR] close zip failed ip=%s err=%v", clientIP, err)
		return
	}
	_ = zipFile.Close()

	// 返回 zip
	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", "kgm2flac_result.zip"))
	http.ServeFile(w, r, zipPath)

	totalDur := time.Since(startReq)
	log.Printf("[UPLOAD END] ip=%s total_files=%d success=%d took=%s", clientIP, len(files), successCount, totalDur)

	// 同步日志：打印每个文件的详情（包含错误）
	for _, rr := range results {
		if rr.err != nil {
			log.Printf("[FILE RESULT] ip=%s name=%s size=%d err=%v", clientIP, rr.origName, rr.size, rr.err)
		} else {
			log.Printf("[FILE RESULT] ip=%s name=%s size=%d out=%s dur=%s", clientIP, rr.origName, rr.size, rr.outPath, rr.duration)
		}
	}
}

// ---------- 辅助函数与原始逻辑（你提供的代码） ----------

// persistUpload 会把 multipart.File 写入一个临时文件并返回路径与 cleanup
func persistUpload(src multipart.File, hdr *multipart.FileHeader) (path string, cleanup func(), err error) {
	// 读取开头 4 字节以便后续可能检查，但同时确保回到起点
	b := make([]byte, 4)
	if _, e := io.ReadFull(src, b); e != nil && e != io.EOF {
		return "", func() {}, e
	}
	if _, e := src.Seek(0, io.SeekStart); e != nil {
		// 有些 multipart.File 的实现可能不支持 Seek，若不支持则用 Copy 到文件时已经从头开始
		// 我们在这里忽略 Seek 错误并尝试继续
	}
	name := fmt.Sprintf("kgm_%s%s", randHex(8), filepath.Ext(hdr.Filename))
	path = filepath.Join(os.TempDir(), name)
	f, e := os.Create(path)
	if e != nil {
		return "", func() {}, e
	}
	defer f.Close()
	if _, e = io.Copy(f, src); e != nil {
		return "", func() {}, e
	}
	return path, func() { _ = os.Remove(path) }, nil
}

// decryptKgmPureGo 保持你原来的纯 Go 解密实现
func decryptKgmPureGo(inPath string) (outPath string, cleanup func(), err error) {
	in, err := os.Open(inPath)
	if err != nil {
		return "", func() {}, err
	}
	defer in.Close()

	dec := kgm.NewDecoder(&common.DecoderParams{Reader: in})
	if err := dec.Validate(); err != nil {
		return "", func() {}, fmt.Errorf("不是有效的 KGM/KGMA/VPR 文件: %w", err)
	}

	outPath = filepath.Join(os.TempDir(), fmt.Sprintf("kgm_dec_%s.bin", randHex(8)))
	out, e := os.Create(outPath)
	if e != nil {
		return "", func() {}, e
	}
	defer out.Close()

	buf := make([]byte, 64*1024)
	for {
		n, e := dec.Read(buf)
		if n > 0 {
			if _, werr := out.Write(buf[:n]); werr != nil {
				return "", func() {}, werr
			}
		}
		if errors.Is(e, io.EOF) {
			break
		}
		if e != nil {
			return "", func() {}, e
		}
	}
	return outPath, func() { _ = os.Remove(outPath) }, nil
}

// sniffAudioExt 嗅探常见音频头（保留你原始逻辑）
func sniffAudioExt(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	head := make([]byte, 12)
	if _, err := io.ReadFull(f, head); err != nil {
		return "", err
	}
	switch {
	case bytes.HasPrefix(head, []byte("fLaC")):
		return ".flac", nil
	case bytes.HasPrefix(head, []byte("ID3")):
		return ".mp3", nil
	case head[0] == 0xFF && (head[1]&0xE0) == 0xE0:
		return ".mp3", nil
	case bytes.HasPrefix(head, []byte("OggS")):
		return ".ogg", nil
	default:
		return "", fmt.Errorf("未知音频头: %x", head)
	}
}

// replaceExt 与 randHex 与 envOr 都保留原样
func replaceExt(name, newExt string) string {
	ext := filepath.Ext(name)
	if ext == "" {
		return name + newExt
	}
	return strings.TrimSuffix(name, ext) + newExt
}

func randHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

// copyFile：在 rename 失败时的安全备份
func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer func() {
		_ = out.Close()
	}()
	if _, err := io.Copy(out, in); err != nil {
		return err
	}
	return out.Sync()
}

// addFileToZip：把磁盘文件加入 zip writer
func addFileToZip(zw *zip.Writer, path string, nameInZip string) error {
	finfo, err := os.Stat(path)
	if err != nil {
		return err
	}
	fh, err := zip.FileInfoHeader(finfo)
	if err != nil {
		return err
	}
	fh.Name = nameInZip
	fh.Method = zip.Deflate
	w, err := zw.CreateHeader(fh)
	if err != nil {
		return err
	}
	in, err := os.Open(path)
	if err != nil {
		return err
	}
	defer in.Close()
	_, err = io.Copy(w, in)
	return err
}

// fileSizeSafe：尝试获取文件大小
func fileSizeSafe(path string) int64 {
	if fi, err := os.Stat(path); err == nil {
		return fi.Size()
	}
	return 0
}
