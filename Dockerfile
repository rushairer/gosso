# 多阶段构建 Dockerfile
# 第一阶段：构建阶段
FROM golang:1.23.3-alpine AS builder

# 设置工作目录
WORKDIR /app

# 安装必要的包
RUN apk add --no-cache git ca-certificates tzdata

# 复制 go mod 文件
COPY go.mod go.sum ./

# 下载依赖
RUN go mod download && go mod verify

# 复制源代码
COPY . .

# 构建应用
ARG VERSION=dev
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
    -ldflags="-s -w -X main.version=${VERSION}" \
    -o gosso ./cmd/gouno

# 第二阶段：运行阶段
FROM alpine:3.18

# 安装必要的包
RUN apk --no-cache add ca-certificates tzdata

# 创建非 root 用户
RUN addgroup -g 1001 -S gosso && \
    adduser -u 1001 -S gosso -G gosso

# 设置工作目录
WORKDIR /app

# 从构建阶段复制二进制文件
COPY --from=builder /app/gosso /app/gosso

# 复制配置文件
COPY --from=builder /app/config /app/config

# 创建日志目录
RUN mkdir -p /app/log && chown -R gosso:gosso /app

# 切换到非 root 用户
USER gosso

# 暴露端口
EXPOSE 8080

# 健康检查
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD wget --no-verbose --tries=1 --spider http://localhost:8080/test/alive || exit 1

# 启动命令
CMD ["./gosso", "web", "--config", "./config/config.yaml", "--address", "0.0.0.0", "--port", "8080"]