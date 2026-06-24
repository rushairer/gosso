DEFAULT:=./cmd
OUTPUT:=./bin/gosso
default: build

VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
COMMIT  ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo "none")
DATE    ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
LDFLAGS := -s -w \
	-X github.com/rushairer/gosso/cmd/gosso.version=$(VERSION) \
	-X github.com/rushairer/gosso/cmd/gosso.commit=$(COMMIT) \
	-X 'github.com/rushairer/gosso/cmd/gosso.date=$(DATE)'

build:
	GOCACHE=$(LOCAL_GOCACHE) go build -buildvcs=false -ldflags="$(LDFLAGS)" -o $(OUTPUT) $(DEFAULT)
	chmod +x $(OUTPUT)

build-debug:
	GOCACHE=$(LOCAL_GOCACHE) go build -buildvcs=false -gcflags "-N -l" -o $(OUTPUT) $(DEFAULT)
	chmod +x $(OUTPUT)

run:
	$(OUTPUT) web

dev:
	@if ! command -v air >/dev/null 2>&1; then \
		go install github.com/air-verse/air@latest; \
	fi
	air -c .air.toml

GOPATH_BIN := $(shell go env GOPATH)/bin
LOCAL_GOCACHE ?= /tmp/gosso-go-build-cache
LOCAL_GOLANGCI_CACHE ?= /tmp/gosso-golangci-lint-cache
GO_TEST_ENV := GOCACHE=$(LOCAL_GOCACHE)
COVERAGE_MIN ?= 70

lint:
	@if ! command -v golangci-lint >/dev/null 2>&1 && ! [ -f "$(GOPATH_BIN)/golangci-lint" ]; then \
		echo "Installing golangci-lint..."; \
		go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.12.2; \
	fi
	@GOLANGCI_LINT=$$(command -v golangci-lint || true); \
	if [ -z "$$GOLANGCI_LINT" ]; then GOLANGCI_LINT="$(GOPATH_BIN)/golangci-lint"; fi; \
	GOCACHE=$(LOCAL_GOCACHE) GOLANGCI_LINT_CACHE=$(LOCAL_GOLANGCI_CACHE) "$$GOLANGCI_LINT" run ./...

lint-fix:
	@if ! command -v golangci-lint >/dev/null 2>&1 && ! [ -f "$(GOPATH_BIN)/golangci-lint" ]; then \
		echo "Installing golangci-lint..."; \
		go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.12.2; \
	fi
	@GOLANGCI_LINT=$$(command -v golangci-lint || true); \
	if [ -z "$$GOLANGCI_LINT" ]; then GOLANGCI_LINT="$(GOPATH_BIN)/golangci-lint"; fi; \
	GOCACHE=$(LOCAL_GOCACHE) GOLANGCI_LINT_CACHE=$(LOCAL_GOLANGCI_CACHE) "$$GOLANGCI_LINT" run --fix ./...
test:
	$(GO_TEST_ENV) go test -race -v -count=1 ./...

test-ui:
	@if ! command -v goconvey >/dev/null 2>&1; then \
		go install github.com/smartystreets/goconvey@latest; \
	fi
	GOFLAGS="-gcflags=all=-l" goconvey -port 9090 -excludedDirs="bin,cmd,config,doc,log,router" -cover

test-integration:
	@echo "🧪 Running integration tests..."
	@echo "📋 Ensure docker-compose.test.yml is running (make docker-test-up)"
	$(GO_TEST_ENV) go test -p 1 -tags=integration -v -count=1 -timeout=180s ./internal/auth/service/ ./internal/session/service/ ./internal/token/service/ ./internal/account/ ./middleware/ ./tests/http/

test-integration-http:
	@echo "🧪 Running HTTP-layer integration tests..."
	@echo "📋 Ensure docker-compose.test.yml is running (make docker-test-up)"
	$(GO_TEST_ENV) go test -p 1 -tags=integration -v -count=1 -timeout=180s ./tests/http/

test-migrations:
	@echo "🔄 Testing migration up/down cycle..."
	@if [ -z "$${DATABASE_URL}" ]; then \
		echo "❌ DATABASE_URL is required. Example: postgres://gosso:gosso@localhost:5434/gosso_test?sslmode=disable"; \
		exit 1; \
	fi
	@if ! command -v migrate >/dev/null 2>&1; then \
		echo "Installing golang-migrate..."; \
		go install github.com/golang-migrate/migrate/v4/cmd/migrate@latest; \
	fi
	migrate -path db/migrations -database "$${DATABASE_URL}" up
	migrate -path db/migrations -database "$${DATABASE_URL}" down -all
	migrate -path db/migrations -database "$${DATABASE_URL}" up
	@echo "✅ Migration up/down/up cycle passed."

architecture-check:
	bash script/check-architecture.sh

coverage-check:
	@echo "📊 Checking coverage threshold..."
	$(GO_TEST_ENV) go test -p 1 -coverprofile=coverage.out -covermode=atomic $$(./script/coverage-packages.sh)
	@cov=$$(GOCACHE=$(LOCAL_GOCACHE) go tool cover -func=coverage.out | grep -E '^total:' | awk '{print $$3}' | sed 's/%//'); \
	echo "Total coverage: $${cov}%"; \
	awk "BEGIN {exit !($${cov} >= $(COVERAGE_MIN))}" || (echo "Coverage $${cov}% is below $(COVERAGE_MIN)% threshold" && exit 1)

critical-coverage-check:
	@echo "📊 Checking critical package coverage thresholds..."
	./script/check-critical-coverage.sh

check: lint test architecture-check coverage-check critical-coverage-check build
	@echo "✅ All checks passed"

coverage:
	@echo "📊 Generating coverage report..."
	$(GO_TEST_ENV) go test -p 1 -coverprofile=coverage.out -covermode=atomic $$(./script/coverage-packages.sh)
	GOCACHE=$(LOCAL_GOCACHE) go tool cover -func=coverage.out | tail -1
	@echo "📄 Full report: go tool cover -html=coverage.out"

docker-dev-up:
	@echo "🚀 启动开发环境..."
	@eval $$(go run script/parse-config.go development) && docker compose -f docker-compose.development.yml up -d
	@echo "✅ 开发环境已启动"
	@echo "🌐 应用地址: http://localhost:$${APP_PORT:-8081}"
	@echo "📧 Mailpit Web UI: http://localhost:$${MAILPIT_WEB_EXTERNAL_PORT:-8026}"

docker-dev-down:
	@echo "🛑 停止开发环境..."
	@eval $$(go run script/parse-config.go development) && docker compose -f docker-compose.development.yml down
	@echo "✅ 开发环境已停止"

docker-dev-logs:
	@echo "📋 查看开发环境日志..."
	@eval $$(go run script/parse-config.go development) && docker compose -f docker-compose.development.yml logs -f

docker-dev:
	docker compose exec gosso sh

docker-test-up:
	@echo "🧪 启动测试环境..."
	@eval $$(go run script/parse-config.go test) && docker compose -f docker-compose.test.yml up -d
	@echo "✅ 测试环境已启动"
	@echo "🌐 应用地址: http://localhost:$${APP_EXTERNAL_PORT:-8082}"
	@echo "📧 Mailpit Web UI: http://localhost:$${MAILPIT_WEB_EXTERNAL_PORT:-8027}"

docker-test-down:
	@echo "🛑 停止测试环境..."
	@eval $$(go run script/parse-config.go test) && docker compose -f docker-compose.test.yml down
	@echo "✅ 测试环境已停止"

docker-test-logs:
	@echo "📋 查看测试环境日志..."
	@eval $$(go run script/parse-config.go test) && docker compose -f docker-compose.test.yml logs -f

docker-prod-up:
	@echo "🚀 启动生产环境..."
	@eval $$(go run script/parse-config.go production) && docker compose -f docker-compose.yml up -d --build
	@echo "✅ 生产环境已启动"

docker-prod-down:
	@echo "🛑 停止生产环境..."
	@eval $$(go run script/parse-config.go production) && docker compose -f docker-compose.yml down
	@echo "✅ 生产环境已停止"

docker-prod-logs:
	@echo "📋 查看生产环境日志..."
	@eval $$(go run script/parse-config.go production) && docker compose -f docker-compose.yml logs -f

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
	@echo "  test-migrations      - Test migration up/down cycle (requires DATABASE_URL)"
	@echo "  check                - Run lint + test + build (pre-submit)"
	@echo "  coverage             - Generate test coverage report"
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
	@echo "🔧 Maintenance Commands:"
	@echo "  clean                - Remove build artifacts"
	@echo "  bench                - Run benchmarks"
	@echo "  security-scan        - Run Trivy security scan on Docker image"
	@echo "  docker-build         - Build Docker image (no push)"
	@echo "  sbom                 - Generate SBOM (requires syft)"
	@echo ""
	@echo "📝 Example Commands:"
	@echo "  examples             - Run all examples"
	@echo "  example-account      - Run account module example"
	@echo "  example-redis        - Run Redis cache example"
	@echo ""
	@echo "🆘 Help Commands:"
	@echo "  help                 - Show this help message"

.PHONY: default build build-debug run dev lint lint-fix test test-ui test-integration test-migrations architecture-check coverage-check critical-coverage-check check coverage docker-dev-up docker-dev docker-dev-down docker-dev-logs docker-test-up docker-test-down docker-test-logs docker-prod-up docker-prod-down docker-prod-logs env-dev env-test env-prod env-all clean bench security-scan docker-build sbom help
# Examples - 示例程序
.PHONY: examples example-account example-redis

examples: example-account example-redis
	@echo "✅ All examples completed"

example-account:
	@echo "========== Running Account Example =========="
	@go run ./examples/account || echo "⚠️  Account example requires database"

example-redis:
	@echo "========== Running Redis Example =========="
	@go run ./examples/redis || echo "⚠️  Redis example requires Redis service"

# Maintenance Commands
clean:
	@echo "🧹 Cleaning build artifacts..."
	rm -rf bin/
	rm -f coverage.out coverage-gate.out
	@echo "✅ Clean complete"

bench:
	@echo "🏃 Running benchmarks..."
	$(GO_TEST_ENV) go test -bench=. -benchmem -run=^$$ ./...

security-scan:
	@echo "🔒 Running security scan..."
	@if command -v trivy >/dev/null 2>&1; then \
		docker build --build-arg VERSION=$$(git describe --tags --always 2>/dev/null || echo "dev") -t gosso-scan:local .; \
		trivy image --severity CRITICAL,HIGH --ignore-unfixed gosso-scan:local; \
	else \
		echo "⚠️  trivy not installed. Install: brew install trivy (macOS) or see https://trivy.dev"; \
		exit 1; \
	fi

docker-build:
	@echo "🐳 Building Docker image (no push)..."
	docker build --build-arg VERSION=$$(git describe --tags --always 2>/dev/null || echo "dev") -t gosso:local .
	@echo "✅ Image tagged as gosso:local"

sbom:
	@echo "📋 Generating SBOM..."
	@if command -v syft >/dev/null 2>&1; then \
		syft dir:. -o cyclonedx-json > gosso-sbom.cdx.json; \
		echo "✅ SBOM written to gosso-sbom.cdx.json"; \
	else \
		echo "⚠️  syft not installed. Install: brew install syft (macOS) or see https://github.com/anchore/syft"; \
		exit 1; \
	fi
