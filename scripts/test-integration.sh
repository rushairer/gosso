#!/bin/bash

set -e

# 颜色输出
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

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
    rm -f coverage-integration-*.out coverage-integration-*.html 2>/dev/null || true
}

# 捕获退出信号，确保清理
trap cleanup EXIT

log_info "🧪 运行集成测试..."

# 集成测试包列表 - 需要数据库和外部服务的包
INTEGRATION_TEST_PACKAGES=(
    "./internal/service/account"     # 账户服务 - 需要数据库
    "./internal/service/email"       # 邮件服务 - 需要 SMTP
    "./internal/task/account"        # 异步任务 - 需要数据库和邮件
    "./internal/database/factory"    # 数据库工厂 - 需要数据库
    "./test/controller"              # 控制器测试 - 需要完整环境
)

log_info "📋 集成测试包 (需要外部服务):"
for pkg in "${INTEGRATION_TEST_PACKAGES[@]}"; do
    echo "  🐳 $pkg"
done

echo ""

# 清理之前的测试环境
cleanup

# 启动测试服务
log_info "🐳 启动测试服务..."
docker-compose -f docker-compose.test.yml up -d

# 等待服务健康检查通过
log_info "⏳ 等待服务启动..."
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

# 设置测试环境变量
export CGO_ENABLED=1

log_info "🚀 开始运行集成测试..."

# 检查包是否存在测试文件
EXISTING_PACKAGES=()
for pkg in "${INTEGRATION_TEST_PACKAGES[@]}"; do
    if ls ${pkg}/*_test.go 1> /dev/null 2>&1; then
        EXISTING_PACKAGES+=("$pkg")
    else
        log_warning "跳过 $pkg (无测试文件)"
    fi
done

if [ ${#EXISTING_PACKAGES[@]} -eq 0 ]; then
    log_warning "没有找到集成测试文件"
    exit 0
fi

# 数据库测试配置 - 使用编译标签分别测试
DATABASES=(
    "mysql"
    "postgres"
    "sqlite"
)

# 运行多数据库集成测试
OVERALL_SUCCESS=true
for db_type in "${DATABASES[@]}"; do
    
    # 转换为大写显示名称
    case $db_type in
        "mysql") db_display="MySQL" ;;
        "postgres") db_display="PostgreSQL" ;;
        "sqlite") db_display="SQLite" ;;
        *) db_display="$db_type" ;;
    esac
    
    log_info "🗄️  测试 $db_display 数据库..."
    
    # 运行当前数据库的集成测试 - 使用 test.yaml 配置和编译标签
    coverage_file="coverage-integration-${db_type}.out"
    if go test -v -race -tags "$db_type" -coverprofile="$coverage_file" \
        --config_path ./config --env test "${EXISTING_PACKAGES[@]}"; then
        log_success "$db_display 集成测试通过"
        
        # 生成当前数据库的覆盖率报告
        if [ -f "$coverage_file" ]; then
            log_info "📊 $db_display 测试覆盖率:"
            go tool cover -func="$coverage_file" | tail -1
            go tool cover -html="$coverage_file" -o "coverage-integration-${db_type}.html"
            log_success "$db_display HTML 报告: coverage-integration-${db_type}.html"
        fi
    else
        log_error "$db_display 集成测试失败"
        OVERALL_SUCCESS=false
    fi
    
    echo ""
done

# 检查总体测试结果
if [ "$OVERALL_SUCCESS" = true ]; then
    log_success "🎉 所有数据库集成测试通过！"
else
    log_error "❌ 部分数据库集成测试失败"
    exit 1
fi

# 显示 Mailpit Web UI 地址
log_info "📧 Mailpit Web UI: http://localhost:8027"

log_success "集成测试完成！"