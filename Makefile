.PHONY: buld

all: test build

clean:
	go clean

test:
	go test -v ./internal/...

build:
	go build ./cmd/...