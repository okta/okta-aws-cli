TEST?=$$(go list ./... |grep -v 'vendor')
GOFMT:=gofumpt
GOLINT=golint
STATICCHECK=staticcheck

ifdef TEST_FILTER
	TEST_FILTER := -run $(TEST_FILTER)
endif

default: build

dep: # Download required dependencies
	go mod tidy

build: fmtcheck
	go install

clean:
	go clean -cache -testcache ./...

clean-all:
	go clean -cache -testcache -modcache ./...

fmt: tools # Format the code
	@$(GOFMT) -l -w .

fmtcheck:
	@gofumpt -d -l .

test:
	go test -race -v $(TEST) || exit 1

test-compile:
	go test -c $(TEST) $(TESTARGS)

lint:
	@golint -set_exit_status ./...

vet:
	@staticcheck -fail all ./...
	@go vet ./...

tools:
	@which $(GOFMT) || go install mvdan.cc/gofumpt@latest
	@which $(GOLINT) || go install golang.org/x/lint/golint@latest
	@which $(STATICCHECK) || go install honnef.co/go/tools/cmd/staticcheck@latest

tools-update:
	@go install mvdan.cc/gofumpt@latest
	@go install golang.org/x/lint/golint@latest
	@go install honnef.co/go/tools/cmd/staticcheck@latest

.PHONY: dep build clean clean-all fmt fmtcheck test test-compile lint vet tools test-compile 
