BUILD := $(shell git describe --tags)

.PHONY: bin
bin:
	go build -ldflags="-s -w -X turnstile-proxy-server/internal/version.Version=$(BUILD)" -o bin/tps ./cmd/tps

.PHONY: lint
lint:
	go tool revive ./...

.PHONY: test
test:
	go test ./...

.PHONY: format
format:
	find . -name "*.go" | xargs go tool goimports -l -w

.PHONY: clean
clean:
	rm -f bin/*
