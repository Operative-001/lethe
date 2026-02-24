.PHONY: build test test-race install clean lint

BINARY := lethe
CMD     := ./cmd/lethe

build:
	go build -o bin/$(BINARY) $(CMD)

install:
	go install $(CMD)

test:
	go test ./... -v -timeout 30s

test-race:
	go test ./... -race -timeout 60s

test-short:
	go test ./... -short -timeout 10s

lint:
	go vet ./...

clean:
	rm -rf bin/

# Run two local test nodes (Alice on :4242, Bob on :4243)
demo-alice:
	mkdir -p /tmp/lethe-alice
	go run $(CMD) keygen --data /tmp/lethe-alice 2>/dev/null || true
	go run $(CMD) daemon --data /tmp/lethe-alice \
		--listen 0.0.0.0:4242 \
		--proxy 127.0.0.1:1080

demo-bob:
	mkdir -p /tmp/lethe-bob
	go run $(CMD) keygen --data /tmp/lethe-bob 2>/dev/null || true
	go run $(CMD) daemon --data /tmp/lethe-bob \
		--listen 0.0.0.0:4243 \
		--proxy 127.0.0.1:1081 \
		--bootstrap 127.0.0.1:4242
