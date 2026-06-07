DEFAULT:=./cmd
OUTPUT:=./bin/gosso
default: build

build:
	go build -buildvcs=false -gcflags "-N -l" -o $(OUTPUT) $(DEFAULT)
	chmod +x $(OUTPUT)

run:
	$(OUTPUT) web

dev:
	@if ! command -v air &> /dev/null; then \
		go install github.com/air-verse/air@latest; \
	fi
	air -c .air.toml

lint:
	@if ! command -v golangci-lint &> /dev/null; then \
		echo "Installing golangci-lint..."; \
		go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest; \
	fi
	golangci-lint run ./...

lint-fix:
	@if ! command -v golangci-lint &> /dev/null; then \
		echo "Installing golangci-lint..."; \
		go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest; \
	fi
	golangci-lint run --fix ./...
test:
	go test -v -count=1 ./...

test-ui:
	@if ! command -v goconvey &> /dev/null; then \
		go install github.com/smartystreets/goconvey@latest; \
	fi
	GOFLAGS="-gcflags=all=-l" goconvey -port 9090 -excludedDirs="bin,cmd,config,doc,log,router" -cover

test-integration:
	@echo "🧪 Running integration tests..."
	@echo "📋 Ensure docker-compose.test.yml is running (make docker-test-up)"
	go test -p 1 -tags=integration -v -count=1 -timeout=120s ./internal/auth/service/ ./internal/session/service/ ./internal/token/service/ ./internal/account/ ./middleware/

docker-dev-up:
	@echo "🚀 启动开发环境..."
	@eval $$(go run script/parse-config.go development) && docker-compose -f docker-compose.development.yml up -d
	@echo "✅ 开发环境已启动"
	@echo "🌐 应用地址: http://localhost:$${APP_PORT:-8081}"
	@echo "📧 Mailpit Web UI: http://localhost:$${MAILPIT_WEB_EXTERNAL_PORT:-8026}"

docker-dev-down:
	@echo "🛑 停止开发环境..."
	@eval $$(go run script/parse-config.go development) && docker-compose -f docker-compose.development.yml down
	@echo "✅ 开发环境已停止"

docker-dev-logs:
	@echo "📋 查看开发环境日志..."
	@eval $$(go run script/parse-config.go development) && docker-compose -f docker-compose.development.yml logs -f

docker-dev:
	docker exec -it gosso-gosso-1 sh

docker-test-up:
	@echo "🧪 启动测试环境..."
	@eval $$(go run script/parse-config.go test) && docker-compose -f docker-compose.test.yml up -d
	@echo "✅ 测试环境已启动"
	@echo "🌐 应用地址: http://localhost:$${APP_EXTERNAL_PORT:-8082}"
	@echo "📧 Mailpit Web UI: http://localhost:$${MAILPIT_WEB_EXTERNAL_PORT:-8027}"

docker-test-down:
	@echo "🛑 停止测试环境..."
	@eval $$(go run script/parse-config.go test) && docker-compose -f docker-compose.test.yml down
	@echo "✅ 测试环境已停止"

docker-test-logs:
	@echo "📋 查看测试环境日志..."
	@eval $$(go run script/parse-config.go test) && docker-compose -f docker-compose.test.yml logs -f

docker-prod-up:
	@echo "🚀 启动生产环境..."
	@eval $$(go run script/parse-config.go production) && docker-compose -f docker-compose.yml up -d --build
	@echo "✅ 生产环境已启动"

docker-prod-down:
	@echo "🛑 停止生产环境..."
	@eval $$(go run script/parse-config.go production) && docker-compose -f docker-compose.yml down
	@echo "✅ 生产环境已停止"

docker-prod-logs:
	@echo "📋 查看生产环境日志..."
	@eval $$(go run script/parse-config.go production) && docker-compose -f docker-compose.yml logs -f

# 环境配置生成命令
env-dev:
	@./script/generate-env.sh development

env-test:
	@./script/generate-env.sh test

env-prod:
	@./script/generate-env.sh production

env-all: env-dev env-test env-prod
	@echo "✅ 所有环境配置已生成"

help:
	@echo "Available commands:"
	@echo ""
	@echo "📦 Build Commands:"
	@echo "  build                - Build the application (default)"
	@echo "  run                  - Run the application"
	@echo ""
	@echo "🚀 Development Commands:"
	@echo "  dev                  - Start development mode with air"
	@echo "  lint                 - Run golangci-lint"
	@echo "  lint-fix             - Run golangci-lint with auto-fix"
	@echo ""
	@echo "🧪 Testing Commands:"
	@echo "  test                 - Run unit tests"
	@echo "  test-ui              - Run tests with goconvey (GUI)"
	@echo "  test-integration     - Run integration tests (requires docker-test-up)"
	@echo ""
	@echo "🐳 Docker Environment Commands:"
	@echo "  docker-dev-up        - Start development environment with Docker"
	@echo "  docker-dev           - Enter development environment with Docker"
	@echo "  docker-dev-down      - Stop development environment"
	@echo "  docker-dev-logs      - View development environment logs"
	@echo "  docker-test-up       - Start test environment with Docker"
	@echo "  docker-test-down     - Stop test environment"
	@echo "  docker-test-logs     - View test environment logs"
	@echo "  docker-prod-up       - Start production environment with Docker"
	@echo "  docker-prod-down     - Stop production environment"
	@echo "  docker-prod-logs     - View production environment logs"
	@echo ""
	@echo "⚙️  Environment Configuration Commands:"
	@echo "  env-dev              - Generate development environment variables"
	@echo "  env-test             - Generate test environment variables"
	@echo "  env-prod             - Generate production environment variables"
	@echo "  env-all              - Generate all environment variables"
	@echo ""
	@echo "📝 Example Commands:"
	@echo "  examples             - Run all examples"
	@echo "  example-account      - Run account module example"
	@echo "  example-redis        - Run Redis cache example"
	@echo "  example-metadata     - Run Metadata usage example"
	@echo ""
	@echo "🆘 Help Commands:"
	@echo "  help                 - Show this help message"

.PHONY: default build run dev lint lint-fix test test-ui test-integration docker-dev-up docker-dev docker-dev-down docker-dev-logs docker-test-up docker-test-down docker-test-logs docker-prod-up docker-prod-down docker-prod-logs env-dev env-test env-prod env-all help
# Examples - 示例程序
.PHONY: examples example-account example-redis example-metadata

examples: example-account example-redis example-metadata
	@echo "✅ All examples completed"

example-account:
	@echo "========== Running Account Example =========="
	@go run ./examples/account || echo "⚠️  Account example requires database"

example-redis:
	@echo "========== Running Redis Example =========="
	@go run ./examples/redis || echo "⚠️  Redis example requires Redis service"

example-metadata:
	@echo "========== Running Metadata Example =========="
	@go run ./examples/metadata
