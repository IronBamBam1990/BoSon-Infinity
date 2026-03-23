VERSION := 2.1.0
LDFLAGS := -s -w
GOBUILD := go build -ldflags="$(LDFLAGS)"

.PHONY: all build test clean docker lint vet race bench

all: build

build:
	$(GOBUILD) -o boson-node ./cmd/node/
	$(GOBUILD) -o boson-cli ./cmd/cli/
	$(GOBUILD) -o boson-miner ./cmd/miner/
	$(GOBUILD) -o boson-oracle ./cmd/oracle/
	$(GOBUILD) -tags wallet -o boson-wallet ./cmd/wallet/
	@echo "=== Built 5 binaries ==="

node:
	$(GOBUILD) -o boson-node ./cmd/node/

cli:
	$(GOBUILD) -o boson-cli ./cmd/cli/

miner:
	$(GOBUILD) -o boson-miner ./cmd/miner/

wallet:
	$(GOBUILD) -tags wallet -o boson-wallet ./cmd/wallet/

oracle:
	$(GOBUILD) -o boson-oracle ./cmd/oracle/

test:
	go test ./core/ ./consensus/ ./security/ ./storage/ ./mempool/ ./p2p/ ./rpc/ -count=1 -timeout 120s

test-v:
	go test ./core/ ./consensus/ ./security/ ./storage/ ./mempool/ ./p2p/ ./rpc/ -v -count=1 -timeout 120s

test-crypto:
	go test ./crypto/ -v -count=1 -timeout 600s

test-all: test test-crypto

race:
	go test ./core/ ./consensus/ ./mempool/ ./security/ -race -count=1 -timeout 60s

bench:
	go test ./crypto/ -bench=. -benchmem -timeout 600s
	go test ./consensus/ -bench=. -benchmem
	go test ./mempool/ -bench=. -benchmem

vet:
	go vet ./...

lint: vet
	@echo "go vet passed"

clean:
	rm -f boson-node boson-cli boson-miner boson-oracle boson-wallet
	rm -f *.exe

docker:
	docker build -t boson-node:$(VERSION) -f Dockerfile .

run: node
	./boson-node

help:
	@echo "Boson Infinity v$(VERSION)"
	@echo ""
	@echo "Targets:"
	@echo "  make build    — Build all 5 binaries"
	@echo "  make node     — Build node only"
	@echo "  make test     — Run all tests"
	@echo "  make bench    — Run benchmarks"
	@echo "  make race     — Race condition detection"
	@echo "  make docker   — Build Docker image"
	@echo "  make clean    — Remove binaries"
	@echo "  make run      — Build and run node"
