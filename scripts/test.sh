#!/bin/bash

set -e

# 颜色输出
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# 日志函数
log_info() {
    echo -e "${BLUE}ℹ️  $1${NC}"
}

log_success() {
    echo -e "${GREEN}✅ $1${NC}"
}

log_warning() {
    echo -e "${YELLOW}⚠️  $1${NC}"
}

log_error() {
    echo -e "${RED}❌ $1${NC}"
}

# 清理函数
cleanup() {
    log_info "清理测试环境..."
    docker-compose -f docker-compose.test.yml down -v --remove-orphans 2>/dev/null || true
    rm -f coverage-*.out coverage-*.html 2>/dev/null || true
}

# 捕获退出信号，确保清理
trap cleanup EXIT

log_info "🚀 启动 GoSSO 测试环境..."

# 清理之前的测试环境
cleanup

# 启动测试服务
log_info "启动测试服务..."
docker-compose -f docker-compose.test.yml up -d

# 等待服务健康检查通过
log_info "等待服务启动..."
timeout=60
elapsed=0
while [ $elapsed -lt $timeout ]; do
    if docker-compose -f docker-compose.test.yml ps | grep -q "healthy"; then
        log_success "服务启动完成"
        break
    fi
    sleep 2
    elapsed=$((elapsed + 2))
    echo -n "."
done

if [ $elapsed -ge $timeout ]; then
    log_error "服务启动超时"
    docker-compose -f docker-compose.test.yml logs
    exit 1
fi

# 额外等待确保服务完全就绪
sleep 5

# 检查 Go 模块
log_info "检查 Go 模块..."
go mod tidy
go mod verify

# 运行代码检查
log_info "🔍 运行代码检查..."
if ! go vet ./...; then
    log_error "代码检查失败"
    exit 1
fi
log_success "代码检查通过"

# 运行格式检查
log_info "🎨 检查代码格式..."
if [ "$(gofmt -s -l . | wc -l)" -gt 0 ]; then
    log_error "以下文件需要格式化:"
    gofmt -s -l .
    exit 1
fi
log_success "代码格式检查通过"

# 运行不同数据库的测试
export CGO_ENABLED=1

# SQLite 测试
log_info "🧪 运行 SQLite 测试..."
if go test -v -race -coverprofile=coverage-sqlite.out -tags sqlite ./...; then
    log_success "SQLite 测试通过"
else
    log_error "SQLite 测试失败"
    exit 1
fi

# MySQL 测试
log_info "🧪 运行 MySQL 测试..."
export MYSQL_DSN="gosso:gosso123@tcp(localhost:3307)/gosso_test?charset=utf8mb4&parseTime=True&loc=Local"
export SMTP_HOST="localhost"
export SMTP_PORT="1025"
export SMTP_FROM="test@gosso.local"

if go test -v -race -coverprofile=coverage-mysql.out -tags mysql ./...; then
    log_success "MySQL 测试通过"
else
    log_error "MySQL 测试失败"
    exit 1
fi

# PostgreSQL 测试
log_info "🧪 运行 PostgreSQL 测试..."
export POSTGRES_DSN="host=localhost user=gosso password=gosso123 dbname=gosso_test port=5433 sslmode=disable"

if go test -v -race -coverprofile=coverage-postgres.out -tags postgres ./...; then
    log_success "PostgreSQL 测试通过"
else
    log_error "PostgreSQL 测试失败"
    exit 1
fi

# 生成覆盖率报告
log_info "📊 生成覆盖率报告..."

echo ""
echo "=== SQLite 覆盖率 ==="
go tool cover -func=coverage-sqlite.out | tail -1

echo ""
echo "=== MySQL 覆盖率 ==="
go tool cover -func=coverage-mysql.out | tail -1

echo ""
echo "=== PostgreSQL 覆盖率 ==="
go tool cover -func=coverage-postgres.out | tail -1

# 生成 HTML 报告
go tool cover -html=coverage-sqlite.out -o coverage-sqlite.html
go tool cover -html=coverage-mysql.out -o coverage-mysql.html
go tool cover -html=coverage-postgres.out -o coverage-postgres.html

log_success "HTML 覆盖率报告已生成:"
log_info "  - coverage-sqlite.html"
log_info "  - coverage-mysql.html"
log_info "  - coverage-postgres.html"

# 显示 MailHog Web UI 地址
log_info "📧 MailHog Web UI: http://localhost:8025"

log_success "🎉 所有测试通过！"