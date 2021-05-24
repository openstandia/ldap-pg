NAME := ldap-pg
VERSION := $(shell git describe --tags --abbrev=0)
REVISION := $(shell git rev-parse --short HEAD)

SRCS    := $(shell find . -type f -name '*.go')

VERSION_OPTS := -X 'main.version=$(VERSION)' -X 'main.revision=$(REVISION)'
WINDOWS_OPTS := -tags netgo -ldflags '-extldflags "-static" $(VERSION_OPTS)'
LINUX_OPTS := -tags netgo -installsuffix netgo -ldflags '-extldflags "-static" $(VERSION_OPTS)'
DARWIN_OPTS := -ldflags '-s -extldflags "-sectcreate __TEXT __info_plist Info.plist" $(VERSION_OPTS)'

GOIMPORTS ?= goimports
GOCILINT ?= golangci-lint

DIST_DIRS := find * -type d -exec

.DEFAULT_GOAL := build 

build: $(SRCS)
	@mkdir -p bin
	@echo "Building $(GOOS)-$(GOARCH)"
ifeq ($(GOOS),darwin)
	go build -o bin $(DARWIN_OPTS)
endif
ifeq ($(GOOS),linux)
	go build -o bin $(LINUX_OPTS)
endif
ifeq ($(GOOS),windows)
	go build -o bin $(WINDOWS_OPTS)
endif

.PHONY: clean
clean:
	rm -rf bin/*
	rm -rf dist/*

.PHONY: lint
lint: ## Run golint and go vet.
	@$(GOCILINT) run --no-config --disable-all --enable=goimports --enable=misspell ./...

.PHONY: dist
dist:
	mkdir -p dist
	@# darwin
	@for arch in "amd64" "386"; do \
		GOOS=darwin GOARCH=$${arch} make build; \
		cd bin; \
		zip ../dist/$(NAME)-$(VERSION)-darwin-$${arch}.zip $(NAME); \
		cd ..; \
	done;
	@# linux
	@for arch in "amd64" "386"; do \
		GOOS=linux GOARCH=$${arch} make build; \
		cd bin; \
		tar zcvf ../dist/$(NAME)-$(VERSION)-linux-$${arch}.tar.gz $(NAME); \
		cd ..; \
	done;
	@# windows
	@for arch in "amd64" "386"; do \
		GOOS=windows GOARCH=$${arch} make build; \
		cd bin; \
		zip ../dist/$(NAME)-$(VERSION)-windows-$${arch}.zip $(NAME).exe; \
		cd ..; \
	done;

.PHONY: test
test:
	go test -cover -v -tags test

.PHONY: it
it:
	go test -cover -v -tags integration

