BRANCH := $(shell git rev-parse --abbrev-ref HEAD)
COMMIT := $(shell git log -1 --format='%H')
APPNAME := qbtc

# do not override user values
ifeq (,$(VERSION))
  VERSION := $(shell git describe --exact-match 2>/dev/null)
  # if VERSION is empty, then populate it with branch name and raw commit hash
  ifeq (,$(VERSION))
    VERSION := $(BRANCH)-$(COMMIT)
  endif
endif

# Update the ldflags with the app, client & server names
ldflags = -X github.com/cosmos/cosmos-sdk/version.Name=$(APPNAME) \
	-X github.com/cosmos/cosmos-sdk/version.AppName=$(APPNAME)d \
	-X github.com/cosmos/cosmos-sdk/version.Version=$(VERSION) \
	-X github.com/cosmos/cosmos-sdk/version.Commit=$(COMMIT)

BUILD_FLAGS := -ldflags '$(ldflags)'

.PHONY: build

build:
	@echo "Building $(APPNAME)d..."
	@GOPRIVATE=github.com/btcq-org/wasmd go build $(BUILD_FLAGS) -o ./build/$(APPNAME)d -mod=readonly ./cmd/$(APPNAME)d
	@echo "Build complete. Binary is located at ./build/$(APPNAME)d"
	@chmod +x ./build/$(APPNAME)d
	@./build/$(APPNAME)d version
	@echo "build bifrost and tools"
	@go build ./cmd/bifrost ./cmd/utxo-indexer
##############
###  Test  ###
##############

test-unit:
	@echo Running unit tests...
	@go test -mod=readonly -v -timeout 30m ./...

test-race:
	@echo Running unit tests with race condition reporting...
	@go test -mod=readonly -v -race -timeout 30m ./...

test-cover:
	@echo Running unit tests and creating coverage report...
	@go test -mod=readonly -v -timeout 30m -coverprofile=$(COVER_FILE) -covermode=atomic ./...
	@go tool cover -html=$(COVER_FILE) -o $(COVER_HTML_FILE)
	@rm $(COVER_FILE)

bench:
	@echo Running unit tests with benchmarking...
	@go test -mod=readonly -v -timeout 30m -bench=. ./...

test: govet test-unit

.PHONY: test test-unit test-race test-cover bench

#################
###  Install  ###
#################

all: install

install:
	@echo "--> ensure dependencies have not been modified"
	@go mod verify
	@echo "--> installing $(APPNAME)d"
	@go install $(BUILD_FLAGS) -mod=readonly ./cmd/$(APPNAME)d

.PHONY: all install
##################
###  Protobuf  ###
##################

# Use this target if you do not want to use Ignite for generating proto files

proto-deps:
	@echo "Installing proto deps"
	@echo "Proto deps present, run 'go tool' to see them"

proto-gen:
	@echo "Generating protobuf files..."
	./scripts/protocgen.sh

.PHONY: proto-gen

###################
###  Protobuf formatting ###
###################
protoVer=0.17.1
protoImageName=ghcr.io/cosmos/proto-builder:$(protoVer)
protoImage=docker run --rm -v $(CURDIR):/workspace --workdir /workspace $(protoImageName)

proto-format:
	@echo "Formatting Protobuf files"
	@$(protoImage) find ./ -name "*.proto" -exec clang-format -i {} \;

proto-format-check:
	@echo "Checking Protobuf formatting"
	@find ./ -name "*.proto" -print0 | xargs -0L1 $(protoImage) clang-format --dry-run -Werror

proto-lint:
	@$(protoImage) buf lint --error-format=json

proto-check-breaking:
	@$(protoImage) buf breaking --against $(HTTPS_GIT)#branch=develop

.PHONY: buf-format buf-format-check

#################
###  Linting  ###
#################

lint:
	@echo "--> Running linter"
	@go tool github.com/golangci/golangci-lint/v2/cmd/golangci-lint run ./... --timeout 15m -v

lint-fix:
	@echo "--> Running linter and fixing issues"
	@go tool github.com/golangci/golangci-lint/v2/cmd/golangci-lint run ./... --fix --timeout 15m

lint-md:
	@echo "--> Running markdown linter"
	@if [ -f "node_modules/.bin/markdownlint-cli2" ]; then \
		npm run lint:md; \
	elif command -v markdownlint-cli2 >/dev/null 2>&1; then \
		markdownlint-cli2 "**/*.md" --config .markdownlint.json; \
	else \
		echo "markdownlint-cli2 not installed."; \
		echo "Install locally: npm install"; \
		echo "Or globally: npm install -g markdownlint-cli2"; \
		echo "Skipping markdown linting..."; \
	fi

lint-md-fix:
	@echo "--> Running markdown linter and fixing issues"
	@if [ -f "node_modules/.bin/markdownlint-cli2" ]; then \
		npm run lint:md:fix; \
	elif command -v markdownlint-cli2 >/dev/null 2>&1; then \
		markdownlint-cli2 --fix "**/*.md" --config .markdownlint.json; \
	else \
		echo "markdownlint-cli2 not installed."; \
		echo "Install locally: npm install"; \
		echo "Or globally: npm install -g markdownlint-cli2"; \
		echo "Skipping markdown linting..."; \
	fi

check: proto-format lint lint-md

.PHONY: lint lint-fix lint-md lint-md-fix check

###################
### Development ###
###################

govet:
	@echo Running go vet...
	@go vet ./...

govulncheck:
	@echo Running govulncheck...
	@go install golang.org/x/vuln/cmd/govulncheck@latest
	@govulncheck ./...

.PHONY: govet govulncheck
