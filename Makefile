DEFAULT:=./cmd
OUTPUT:=./bin/gouno

default: build

build: build.postgres

build.%:
	go build -tags $* -buildvcs=false -gcflags "-N -l" -o $(OUTPUT) $(DEFAULT)
	@echo "Built $* version: $(OUTPUT)"

run:
	$(OUTPUT) web

dev: dev.postgres

dev.%:
	@if ! command -v air &> /dev/null; then \
		go install github.com/air-verse/air@latest; \
	fi
	DB=$* air -c .air.toml
	
# Docker 环境管理
docker-dev-up:
	@echo "🚀 启动开发环境..."
	@eval $$(go run scripts/parse-config.go development) && docker-compose -f docker-compose.development.yml up -d
	@echo "✅ 开发环境已启动"
	@echo "🌐 应用地址: http://localhost:$${APP_PORT:-8081}"
	@echo "📧 Mailpit Web UI: http://localhost:$${MAILPIT_WEB_EXTERNAL_PORT:-8026}"

docker-dev-down:
	@echo "🛑 停止开发环境..."
	@eval $$(go run scripts/parse-config.go development) && docker-compose -f docker-compose.development.yml down
	@echo "✅ 开发环境已停止"

docker-dev-logs:
	@echo "📋 查看开发环境日志..."
	@eval $$(go run scripts/parse-config.go development) && docker-compose -f docker-compose.development.yml logs -f

docker-prod-up:
	@echo "🚀 启动生产环境..."
	@eval $$(go run scripts/parse-config.go production) && docker-compose -f docker-compose.production.yml up -d
	@echo "✅ 生产环境已启动"
	@echo "🌐 应用地址: http://localhost:$${APP_PORT:-8080}"

docker-prod-down:
	@echo "🛑 停止生产环境..."
	@eval $$(go run scripts/parse-config.go production) && docker-compose -f docker-compose.production.yml down
	@echo "✅ 生产环境已停止"

docker-prod-logs:
	@echo "📋 查看生产环境日志..."
	@eval $$(go run scripts/parse-config.go production) && docker-compose -f docker-compose.production.yml logs -f

# 测试命令 (使用 Docker 环境)
test: test-unit

test-unit:
	@echo "运行单元测试..."
	@./scripts/test-unit.sh

test-integration:
	@echo "运行集成测试..."
	@./scripts/test-integration.sh

test-all: test-unit test-integration

test-coverage:
	@echo "生成覆盖率报告..."
	@go test -coverprofile=coverage.out ./...
	@go tool cover -html=coverage.out -o coverage.html
	@echo "覆盖率报告已生成: coverage.html"

test-clean:
	@echo "清理测试环境..."
	@./scripts/test-clean.sh

# 传统测试命令 (仅用于特殊需求)
test-legacy.%:
	@echo "运行传统 $* 测试..."
	@GO111MODULE=on go test -tags=$* -v ./...

clean:
	rm -rf .$(OUTPUT)

help:
	@echo "Available commands:"
	@echo ""
	@echo "📦 Build Commands:"
	@echo "  build                - Build postgres version (default)"
	@echo ""
	@echo "🚀 Development Commands:"
	@echo "  run                  - Run the application locally"
	@echo "  dev                  - Start development mode with air (postgres)"
	@echo ""
	@echo "🐳 Docker Environment Commands:"
	@echo "  docker-dev-up        - Start development environment with Docker"
	@echo "  docker-dev-down      - Stop development environment"
	@echo "  docker-dev-logs      - View development environment logs"
	@echo "  docker-prod-up       - Start production environment with Docker"
	@echo "  docker-prod-down     - Stop production environment"
	@echo "  docker-prod-logs     - View production environment logs"
	@echo ""
	@echo "🧪 Testing Commands:"
	@echo "  test                 - Run unit tests (default)"
	@echo "  test-unit            - Run unit tests only"
	@echo "  test-integration     - Run integration tests with Docker"
	@echo "  test-all             - Run all tests (unit + integration)"
	@echo "  test-coverage        - Generate coverage report"
	@echo "  test-clean           - Clean test environment"
	@echo "  test-legacy.postgres - Legacy: Run tests with postgres tags"
	@echo ""
	@echo "🧹 Utility Commands:"
	@echo "  clean                - Clean build artifacts"
	@echo "  help                 - Show this help message"

.PHONY: default build run dev docker-dev-up docker-dev-down docker-dev-logs docker-prod-up docker-prod-down docker-prod-logs test test-unit test-integration test-all test-coverage test-clean clean help