# ========= 1. 构建阶段 =========
FROM harbor.tianxiang.love:30443/library/golang:1.23  AS builder

ENV GOPROXY=https://goproxy.cn,direct

WORKDIR /build

# 先创建 go.mod 文件
RUN go mod init kgm2flac

# 复制所有文件
COPY . .

# 下载依赖并构建
RUN go mod tidy && \
    CGO_ENABLED=0 GOOS=linux go build -o /kgm2flac main.go

# ========= 2. 运行阶段 =========
FROM harbor.tianxiang.love:30443/library/debian:bookworm-slim

# 设置国内镜像源
RUN sed -i 's/deb.debian.org/mirrors.aliyun.com/g' /etc/apt/sources.list.d/debian.sources 

# 安装依赖
RUN apt-get update && \
    apt-get install -y --no-install-recommends ffmpeg zip ca-certificates && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY --from=builder /kgm2flac /usr/local/bin/kgm2flac

ENV ADDR=:8080

EXPOSE 8080

ENTRYPOINT ["kgm2flac"]
