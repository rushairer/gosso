#!/bin/bash

# 颜色输出
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
NC='\033[0m'

log_info() {
    echo -e "${YELLOW}🧹 $1${NC}"
}

log_success() {
    echo -e "${GREEN}✅ $1${NC}"
}

log_info "清理测试环境和文件..."

# 停止并删除测试容器
docker-compose -f docker-compose.test.yml down -v --remove-orphans 2>/dev/null || true

# 清理覆盖率文件
rm -f coverage*.out coverage*.html 2>/dev/null || true

# 清理测试缓存
go clean -testcache

# 清理构建缓存
go clean -cache

log_success "清理完成！"