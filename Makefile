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
	
test: test.sqlite

test.%:
	GO111MODULE=on go test -tags=$* -v ./...

# 新增测试命令
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

clean:
	rm -rf .$(OUTPUT)

help:
	@echo "Available commands:"
	@echo "  build          - Build postgres version (default)"
	@echo "  build.mysql    - Build mysql version"
	@echo "  build.postgres - Build postgres version"
	@echo "  build.sqlite   - Build sqlite version"
	@echo "  run            - Run the application"
	@echo "  dev            - Start development mode with air (postgres)"
	@echo "  dev.mysql      - Start development mode with air (mysql)"
	@echo "  dev.postgres   - Start development mode with air (postgres)"
	@echo "  dev.sqlite     - Start development mode with air (sqlite)"
	@echo "  test             - Run tests (sqlite)"
	@echo "  test.mysql       - Run tests with mysql tags"
	@echo "  test.postgres    - Run tests with postgres tags"
	@echo "  test.sqlite      - Run tests with sqlite tags"
	@echo "  test-unit        - Run unit tests only"
	@echo "  test-integration - Run integration tests with Docker"
	@echo "  test-all         - Run all tests"
	@echo "  test-coverage    - Generate coverage report"
	@echo "  test-clean       - Clean test environment"
	@echo "  clean            - Clean build artifacts"
	@echo "  help             - Show this help message"

.PHONY: default build run dev test test-unit test-integration test-all test-coverage test-clean clean help
