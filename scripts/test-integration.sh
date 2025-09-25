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
    log_info "🧹 清理测试环境..."
    
    # 停止 Docker 服务
    docker-compose -f docker-compose.test.yml down -v --remove-orphans 2>/dev/null || true
    
    # 清理覆盖率文件
    rm -f coverage-integration-*.out coverage-integration-*.html 2>/dev/null || true
}

# 捕获退出信号，确保清理
trap cleanup EXIT

# 解析测试配置
log_info "📋 解析测试配置..."
if command -v go &> /dev/null; then
    # 使用 Go 脚本解析配置 (最可靠，项目本身就是 Go)
    eval "$(go run scripts/parse-config.go test)"
elif command -v yq &> /dev/null; then
    # 备用方案：使用 yq (需要手动安装)
    log_warning "⚠️  使用 yq 备用方案，推荐使用 Go 解析"
    log_error "❌ yq 方案已移除，请使用: go run scripts/parse-config.go test"
    exit 1
else
    log_error "需要 Go 环境来解析配置文件"
    log_info "解决方案:"
    log_info "  确保 Go 已安装: go version"
    log_info "  直接使用: go run scripts/parse-config.go test"
    exit 1
fi

log_info "🧪 开始集成测试..."

# 集成测试包列表
INTEGRATION_TEST_PACKAGES=(
    "./internal/service/account"     # 账户服务 - 需要数据库
    "./internal/service/email"       # 邮件服务 - 需要 SMTP
    "./internal/task/account"        # 异步任务 - 需要数据库和邮件
    "./internal/database/factory"    # 数据库工厂 - 需要数据库
    "./test/controller"              # 控制器测试 - 需要完整环境
)

log_info "📋 集成测试包列表:"
for pkg in "${INTEGRATION_TEST_PACKAGES[@]}"; do
    echo "  🐳 $pkg"
done
echo ""

# 清理之前的测试环境
log_info "🧹 清理之前的测试环境..."
docker-compose -f docker-compose.test.yml down -v --remove-orphans 2>/dev/null || true

# 启动测试服务 (基于 docker-compose.test.yml)
log_info "🐳 启动测试服务..."
docker-compose -f docker-compose.test.yml up -d

# 等待服务启动
log_info "⏳ 等待服务启动..."
sleep 15

# 简单检查服务状态
log_info "🔍 检查服务状态..."
if docker-compose -f docker-compose.test.yml ps | grep -q "Up"; then
    log_success "服务启动完成"
else
    log_warning "部分服务可能未完全启动，继续测试..."
fi

# 检查包是否存在测试文件
EXISTING_PACKAGES=()
for pkg in "${INTEGRATION_TEST_PACKAGES[@]}"; do
    if find "$pkg" -name "*_test.go" -type f 2>/dev/null | head -1 | grep -q "_test.go" 2>/dev/null; then
        EXISTING_PACKAGES+=("$pkg")
        log_info "✅ 找到测试文件: $pkg"
    else
        log_warning "跳过 $pkg (无测试文件)"
    fi
done

if [ ${#EXISTING_PACKAGES[@]} -eq 0 ]; then
    log_warning "没有找到集成测试文件"
    exit 0
fi

log_info "📋 将要测试的包 (${#EXISTING_PACKAGES[@]} 个):"
for pkg in "${EXISTING_PACKAGES[@]}"; do
    echo "  ✅ $pkg"
done
echo ""

# 数据库测试配置 (使用编译标签)
DATABASES=(
    "mysql"
    "postgres" 
    "sqlite"
)

# 设置测试环境变量
export CGO_ENABLED=1

log_info "🚀 开始编译标签驱动的数据库测试..."
log_info "💡 Go 测试代码将从 config/test.yaml 读取配置"
echo ""

# 运行多数据库集成测试
OVERALL_SUCCESS=true
for db_type in "${DATABASES[@]}"; do
    
    # 转换为显示名称
    case $db_type in
        "mysql") db_display="MySQL" ;;
        "postgres") db_display="PostgreSQL" ;;
        "sqlite") db_display="SQLite" ;;
        *) db_display="$db_type" ;;
    esac
    
    log_info "🗄️  测试 $db_display 数据库 (编译标签: $db_type)..."
    
    # 运行当前数据库的集成测试
    coverage_file="coverage-integration-${db_type}.out"
    
    log_info "🧪 运行 $db_display 集成测试..."
    
    # 构建测试命令 - 使用编译标签
    test_cmd="go test -v -race -tags $db_type -coverprofile=$coverage_file"
    
    # 添加包列表
    for pkg in "${EXISTING_PACKAGES[@]}"; do
        test_cmd="$test_cmd $pkg"
    done
    
    log_info "执行命令: $test_cmd"
    
    if eval "$test_cmd" 2>&1; then
        log_success "$db_display 集成测试通过"
        
        # 生成覆盖率报告
        if [ -f "$coverage_file" ]; then
            log_info "📊 $db_display 测试覆盖率:"
            go tool cover -func="$coverage_file" | tail -1 2>/dev/null || echo "无覆盖率数据"
            go tool cover -html="$coverage_file" -o "coverage-integration-${db_type}.html" 2>/dev/null || true
            log_success "$db_display HTML 报告: coverage-integration-${db_type}.html"
        fi
    else
        log_error "$db_display 集成测试失败"
        OVERALL_SUCCESS=false
    fi
    
    echo ""
done

# 检查总体测试结果
echo ""
if [ "$OVERALL_SUCCESS" = true ]; then
    log_success "🎉 所有集成测试通过！"
    
    # 显示测试环境信息
    echo ""
    log_info "📊 测试环境信息:"
    echo "  🐳 Docker Compose: docker-compose.test.yml (配置来源: config/test.yaml)"
    echo "  🗄️  MySQL: 127.0.0.1:${MYSQL_EXTERNAL_PORT}"
    echo "  🐘 PostgreSQL: 127.0.0.1:${POSTGRES_EXTERNAL_PORT}"
    echo "  📧 Mailpit SMTP: 127.0.0.1:${SMTP_EXTERNAL_PORT}"
    echo "  📧 Mailpit Web UI: http://localhost:${MAILPIT_WEB_EXTERNAL_PORT}"
    echo "  🔴 Redis: 127.0.0.1:${REDIS_EXTERNAL_PORT}"
    echo ""
    log_info "💡 统一配置源: config/test.yaml"
    log_info "🏗️  编译标签分离: mysql, postgres, sqlite"
    
else
    log_error "❌ 部分集成测试失败"
    exit 1
fi

log_success "集成测试完成！"