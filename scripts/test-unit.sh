#!/bin/bash

set -e

# 颜色输出
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m'

log_info() {
    echo -e "${BLUE}ℹ️  $1${NC}"
}

log_success() {
    echo -e "${GREEN}✅ $1${NC}"
}

log_info "🧪 运行单元测试..."

# 运行单元测试（排除需要数据库的测试）
export CGO_ENABLED=1

# 只运行快速的单元测试
go test -v -race -short -coverprofile=coverage-unit.out ./internal/service/captcha ./utility

# 生成覆盖率报告
if [ -f coverage-unit.out ]; then
    log_info "📊 单元测试覆盖率:"
    go tool cover -func=coverage-unit.out | tail -1
    go tool cover -html=coverage-unit.out -o coverage-unit.html
    log_success "HTML 报告: coverage-unit.html"
fi

log_success "单元测试完成！"