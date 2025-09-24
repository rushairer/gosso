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

# 运行单元测试（排除需要数据库和外部服务的测试）
export CGO_ENABLED=1

# 单元测试包列表 - 不依赖数据库和外部服务的包
UNIT_TEST_PACKAGES=(
    "./internal/service/captcha"     # 验证码服务 - 纯逻辑，无外部依赖
    "./internal/context"             # 上下文处理 - 纯逻辑
    "./utility"                      # 工具函数 - 纯逻辑
    "./middleware"                   # 中间件 - HTTP 处理逻辑
    "./config"                       # 配置处理 - 文件读取和解析
    "./internal/domain/account"      # 领域模型 - 数据结构定义
    "./internal/repository/account"  # 数据仓库 - 使用 gomonkey mock，无真实数据库依赖
    "./cmd"                          # 命令行工具
    "./router"                       # 路由配置 - 不涉及实际请求
)

# 需要数据库的包（集成测试）
INTEGRATION_TEST_PACKAGES=(
    "./internal/service/account"     # 账户服务 - 需要数据库
    "./internal/service/email"       # 邮件服务 - 需要 SMTP
    "./internal/task/account"        # 异步任务 - 需要数据库和邮件
    "./internal/database/factory"    # 数据库工厂 - 需要数据库
    "./test/controller"              # 控制器测试 - 需要完整环境
)

log_info "📋 单元测试包 (无外部依赖):"
for pkg in "${UNIT_TEST_PACKAGES[@]}"; do
    echo "  ✅ $pkg"
done

echo ""
log_info "📋 集成测试包 (需要外部服务):"
for pkg in "${INTEGRATION_TEST_PACKAGES[@]}"; do
    echo "  🐳 $pkg"
done

echo ""
log_info "🚀 开始运行单元测试..."

# 检查包是否存在测试文件
EXISTING_PACKAGES=()
for pkg in "${UNIT_TEST_PACKAGES[@]}"; do
    if ls ${pkg}/*_test.go 1> /dev/null 2>&1; then
        EXISTING_PACKAGES+=("$pkg")
    else
        echo "  ⚠️  跳过 $pkg (无测试文件)"
    fi
done

if [ ${#EXISTING_PACKAGES[@]} -eq 0 ]; then
    log_info "⚠️  没有找到单元测试文件"
    exit 0
fi

# 运行单元测试
go test -v -race -short -coverprofile=coverage-unit.out "${EXISTING_PACKAGES[@]}"

# 生成覆盖率报告
if [ -f coverage-unit.out ]; then
    log_info "📊 单元测试覆盖率:"
    go tool cover -func=coverage-unit.out | tail -1
    go tool cover -html=coverage-unit.out -o coverage-unit.html
    log_success "HTML 报告: coverage-unit.html"
fi

log_success "单元测试完成！"