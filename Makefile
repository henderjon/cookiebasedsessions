export TESTSALT = 86A96823-FD69-4556-8960-34887473750A

all: test

.PHONY: dep
dep:
	go mod tidy
	go mod vendor

.PHONY: check
check: dep
	golint
	goimports -w ./
	gofmt -w ./
	go vet

.PHONY: test-vendor
test-vendor:
	go test -v -mod=vendor -covermode=count ./...

.PHONY: test
test: check
	go test -v -covermode=count ./...

