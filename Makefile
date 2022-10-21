TEST?=$$(go list ./... |grep -v 'vendor')
ERRCHECK=errcheck
GOCONST=goconst
GOCYCLO=gocyclo
GOFMT:=gofumpt
GOLINT=golint
SHADOW=shadow
STATICCHECK=staticcheck
GOBIN ?= $(shell go env GOPATH)/bin

ifdef TEST_FILTER
	TEST_FILTER := -run $(TEST_FILTER)
endif

default: build

dep: # Download required dependencies
	go mod tidy

build: fmtcheck
	go build -o $(GOBIN)/okta-aws-cli cmd/okta-aws-cli/main.go

clean:
	go clean -cache -testcache ./...

clean-all:
	go clean -cache -testcache -modcache ./...

fmt: tools # Format the code
	@$(GOFMT) -l -w .

test:
	go test -race -v $(TEST) || exit 1

test-compile:
	go test -c $(TEST) $(TESTARGS)

errcheck:
	@errcheck ./...

fmtcheck:
	@gofumpt -d -l .

goconst:
	$(GOBIN)/goconst ./...

gocyclo:
	@gocyclo -over 3 .

lint:
	@golint -set_exit_status ./...

shadow:
	@go vet -vettool=$(which shadow) ./...

staticcheck:
	$(GOBIN)/staticcheck -fail all ./...

vet:
	@go vet ./...

# TODO add in gocyclo after code is cleaned up further
qc: fmtcheck errcheck goconst shadow lint staticcheck vet

tools:
	@which $(ERRCHECK) || go install github.com/kisielk/errcheck@latest
	@which $(GOCONST) || go install github.com/jgautheron/goconst/cmd/goconst@latest
	@which $(GOCYCLO) || go install github.com/fzipp/gocyclo/cmd/gocyclo@latest
	@which $(GOFMT) || go install mvdan.cc/gofumpt@latest
	@which $(GOLINT) || go install golang.org/x/lint/golint@latest
	@which $(SHADOW) || go mod download golang.org/x/tools
	@which $(STATICCHECK) || go install honnef.co/go/tools/cmd/staticcheck@latest

tools-update:
	@go install github.com/kisielk/errcheck@latest
	@go install github.com/jgautheron/goconst/cmd/goconst@latest
	@go install github.com/fzipp/gocyclo/cmd/gocyclo@latest
	@go install mvdan.cc/gofumpt@latest
	@go install golang.org/x/lint/golint@latest
	@go mod download golang.org/x/tools
	@go install honnef.co/go/tools/cmd/staticcheck@latest

.PHONY: dep build clean clean-all fmt fmtcheck test test-compile lint vet tools test-compile 
