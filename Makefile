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
	
# 测试命令 (使用 Docker 环境)
test: test-unit

test-unit:
	@echo "运行单元测试..."
	@./scripts/test-unit.sh

test-integration:
	@echo "运行集成测试..."
	@./scripts/test.sh

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
	@echo "  build                - Build postgres version (default)"
	@echo "  build.mysql          - Build mysql version"
	@echo "  build.postgres       - Build postgres version"
	@echo "  build.sqlite         - Build sqlite version"
	@echo "  run                  - Run the application"
	@echo "  dev                  - Start development mode with air (postgres)"
	@echo "  dev.mysql            - Start development mode with air (mysql)"
	@echo "  dev.postgres         - Start development mode with air (postgres)"
	@echo "  dev.sqlite           - Start development mode with air (sqlite)"
	@echo "  test                 - Run unit tests (default)"
	@echo "  test-unit            - Run unit tests only"
	@echo "  test-integration     - Run integration tests with Docker"
	@echo "  test-all             - Run all tests (unit + integration)"
	@echo "  test-coverage        - Generate coverage report"
	@echo "  test-clean           - Clean test environment"
	@echo "  test-legacy.mysql    - Legacy: Run tests with mysql tags"
	@echo "  test-legacy.postgres - Legacy: Run tests with postgres tags"
	@echo "  test-legacy.sqlite   - Legacy: Run tests with sqlite tags"
	@echo "  clean                - Clean build artifacts"
	@echo "  help                 - Show this help message"

.PHONY: default build run dev test test-unit test-integration test-all test-coverage test-clean clean help