FROM golang:1.22 AS builder

WORKDIR /app

# 安装编译依赖
RUN apt-get update && apt-get install -y gcc musl-dev sqlite3 libsqlite3-dev

# 复制go mod文件
COPY go.mod go.sum ./
RUN go mod download

# 复制源代码
COPY . .

# 编译应用
RUN CGO_ENABLED=1 GOOS=linux go build -o wblog main.go

# 最终镜像
FROM debian:bookworm-slim

WORKDIR /app

# 安装运行时依赖
RUN apt-get update && apt-get install -y ca-certificates sqlite3 && rm -rf /var/lib/apt/lists/*

# 复制编译好的二进制文件和必要的配置文件
COPY --from=builder /app/wblog /app/
COPY --from=builder /app/conf /app/conf
COPY --from=builder /app/static /app/static
COPY --from=builder /app/views /app/views

# 创建数据目录并设置权限
RUN mkdir -p /app/data && chmod 777 /app/data

# 设置环境变量
ENV GIN_MODE=release

# 暴露端口
EXPOSE 8090

# 启动命令
CMD ["/app/wblog"]