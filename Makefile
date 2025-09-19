DEFAULT:=./cmd
OUTPUT:=./bin/gouno

default: build

build: build.postgres

build.%:
	go build -tags $* -buildvcs=false -gcflags "-N -l" -o $(OUTPUT) $(DEFAULT)
	@echo "Built $* version: $(OUTPUT)"

run:
	$(OUTPUT) web

dev:
	@if ! command -v air &> /dev/null; then \
		go install github.com/air-verse/air@latest; \
	fi
	air -c .air.toml
	
test: test.sqlite

test.%:
	GO111MODULE=on go test -tags=$* -v ./...

clean:
	rm -rf ./bin/gouno

help:
	@echo "Available commands:"
	@echo "  build          - Build postgres version (default)"
	@echo "  run            - Run the application"
	@echo "  dev            - Start development mode with air"
	@echo "  test           - Run tests"
	@echo "  clean          - Clean build artifacts"
	@echo "  help           - Show this help message"

.PHONY: build mysql postgres sqlite build-mysql build-postgres build-sqlite dev test run clean help
