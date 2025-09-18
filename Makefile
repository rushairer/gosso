DEFAULT:=./cmd
OUTPUT:=./bin/gouno
default: build

build:
	go build -tags postgres -buildvcs=false -gcflags "-N -l" -o $(OUTPUT) $(DEFAULT)
	chmod +x $(OUTPUT)

build-mysql:
	go build -tags mysql -buildvcs=false -gcflags "-N -l" -o $(OUTPUT) $(DEFAULT)
	chmod +x $(OUTPUT)

run:
	$(OUTPUT) web

dev:
	@if ! command -v air &> /dev/null; then \
		go install github.com/air-verse/air@latest; \
	fi
	air -c .air.toml
.PHONY: test
test:
	@if ! command -v goconvey &> /dev/null; then \
		go install github.com/smartystreets/goconvey@latest; \
	fi
	GOFLAGS="-gcflags=all=-l" goconvey -port 9090 -excludedDirs="bin,cmd,config,doc,log,router" -cover