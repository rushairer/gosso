#!/bin/bash

# 环境配置生成脚本
# 用法: ./scripts/generate-env.sh <environment>
# 示例: ./scripts/generate-env.sh development

set -e

# 检查参数
if [ $# -eq 0 ]; then
    echo "❌ 用法: $0 <environment>"
    echo "可用环境: development, test, production"
    exit 1
fi

ENVIRONMENT=$1
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
ENV_FILE="$PROJECT_ROOT/.env.$ENVIRONMENT"

echo "🔧 生成 $ENVIRONMENT 环境配置..."
echo "📁 配置文件位置: deploy/environments.yaml"

# 检查 parse-config.go 是否存在
if [ ! -f "$SCRIPT_DIR/parse-config.go" ]; then
    echo "❌ 未找到 parse-config.go 文件"
    exit 1
fi

# 编译并运行 parse-config.go
cd "$PROJECT_ROOT"

echo "📦 编译配置解析器..."
go build -o "$SCRIPT_DIR/parse-config" "$SCRIPT_DIR/parse-config.go"

echo "⚙️  解析 $ENVIRONMENT 环境配置..."
"$SCRIPT_DIR/parse-config" "$ENVIRONMENT" > "$ENV_FILE"

# 清理临时文件
rm -f "$SCRIPT_DIR/parse-config"

echo "✅ 环境配置已生成: $ENV_FILE"
echo ""
echo "📋 生成的环境变量:"
echo "----------------------------------------"
cat "$ENV_FILE"
echo "----------------------------------------"
echo ""
echo "💡 使用方法:"
echo "   source $ENV_FILE"
echo "   或者在 docker-compose 中使用: --env-file $ENV_FILE"