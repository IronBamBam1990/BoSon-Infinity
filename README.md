## Boson Infinity — Energy-Defined Layer-0 Blockchain

Boson Infinity is an energy-defined Layer-0 blockchain designed around **real computational cost**, **GPU-efficient Proof-of-Work**, and **strictly transparent monetary rules**.

The protocol links coin issuance and valuation directly to measurable energy and hash cost, eliminating speculative supply manipulation, hidden incentives, and artificial scarcity models.

Boson Infinity is built from first principles as a minimal, auditable base layer — without EVM, without smart-contract bloat, and without centralized control.

---

## Key Features

* **SHA-512 + DAG Memory-Hard Proof-of-Work** optimized for modern GPUs
* **256MB+ DAG dataset** — GPU VRAM advantage, ASIC-resistant
* **High-throughput GPU mining** with low hardware entry barrier
* **WebSocket mining protocol** with share difficulty for pool support
* **Energy-defined monetary model**
  (coin cost derived from real joules per hash and electricity pricing)
* **Fixed hard cap supply** (50M BOS) with deterministic halving schedule
* **Zero premine, zero founders' allocation, zero VC issuance**
* **Treasury funded exclusively via protocol-level block rewards (20%)**
* **Multi-sig bridge** to ERC-20 (M-of-N guardian signatures)
* **Wallet encryption** — Argon2id + AES-256-GCM, 24-word mnemonic backup
* **Merkle inclusion proofs** — SPV/light client verification
* **Built-in block explorer** and Prometheus metrics
* **Fully transparent math and consensus rules**
* **No hidden mechanics, no discretionary minting**

---

## Architecture

```
cmd/node/       — Full blockchain node (RPC + P2P + Mining + Explorer)
cmd/miner/      — CPU miner (HTTP polling + WebSocket)
cmd/wallet/     — Desktop wallet with Argon2id encryption
cmd/cli/        — Command-line interface
cmd/oracle/     — Energy oracle / aggregator
core/           — Types, config, consensus parameters
crypto/         — SHA-512 hashing, DAG PoW, Ed25519, merkle proofs, mnemonic
consensus/      — Rewards, difficulty retarget, block/TX validation, energy economics
storage/        — BBolt database, TX index, checkpoints, pruning
mempool/        — Indexed mempool with O(1) lookup, fee-priority ordering
p2p/            — Peer discovery, chain sync, fork resolution, ban scoring
rpc/            — HTTP API, WebSocket mining, block explorer, metrics
security/       — Rate limiting, API auth, CORS, security headers
```

---

## Quick Start

```bash
# Build all 5 binaries
make build

# Or manually:
go build -o boson-node ./cmd/node/
go build -o boson-miner ./cmd/miner/
go build -o boson-cli ./cmd/cli/
go build -o boson-oracle ./cmd/oracle/
go build -tags wallet -o boson-wallet ./cmd/wallet/

# Configure
cp boson.env.example boson.env
# Edit boson.env — set BOSON_API_KEY and BOSON_TREASURY_ADDR

# Run node
./boson-node

# Check status
./boson-cli status
./boson-cli stats

# Open block explorer
# http://localhost:8080/explorer

# Prometheus metrics
# http://localhost:8080/metrics
```

## Docker

```bash
# Build and run with Docker Compose
docker-compose up -d

# Or standalone
docker build -t boson-node .
docker run -p 8080:8080 -p 8081:8081 \
  -e BOSON_API_KEY=<key> \
  -e BOSON_TREASURY_ADDR=<addr> \
  boson-node
```

---

## Mining

Miners connect via HTTP polling (`/getWork` + `/submitWork`) or **WebSocket** (`/ws/mining`) for push-based job delivery.

```bash
# CPU miner (HTTP polling)
export BOSON_NODE_URL=http://localhost:8080
export BOSON_API_KEY=<your-api-key>
export BOSON_WALLET=<your-40-hex-address>
./boson-miner

# CPU miner (WebSocket — recommended, gets new jobs pushed instantly)
./boson-miner --ws
```

The PoW algorithm uses SHA-512 with a memory-hard DAG component (similar to Ethash). DAG size starts at 256MB and grows 8MB per epoch (30,000 blocks). Legacy SHA-512 PoW is used for blocks below height 1000, then DAG PoW activates.

Share difficulty support enables pool-style mining with lower difficulty submissions.

---

## Wallet

```bash
# Set encryption passphrase (HIGHLY recommended)
export BOSON_WALLET_PASS=YourStrongPassphrase

# Start wallet GUI
./boson-wallet
# Opens http://localhost:8090

# Wallet features:
# - Argon2id + AES-256-GCM key encryption
# - 24-word mnemonic seed phrase for backup
# - Auto-migration from plaintext to encrypted on startup
# - Send/receive BOS, view balance, network stats
```

---

## P2P Network

Nodes discover peers automatically via seed nodes and gossip protocol.

```bash
# Set seed nodes (comma-separated)
export BOSON_SEED_NODES=http://seed1.example:8081,http://seed2.example:8081
```

Features:
* **Heartbeat** — ping peers every 30s, remove dead peers after 3 failures
* **Chain sync** — new nodes download the full chain from peers in batches
* **Fork resolution** — detects forks, finds common ancestor, reorgs up to 100 blocks
* **TX propagation** — accepted transactions are broadcast to all peers
* **Ban scoring** — peers penalized for invalid blocks (+20), wrong network (+100 instant ban)
* **Protocol versioning** — incompatible peers auto-disconnected

---

## API Endpoints

### Public
| Endpoint | Method | Description |
|----------|--------|-------------|
| `/health` | GET | Node health check |
| `/explorer` | GET | Built-in block explorer UI |
| `/metrics` | GET | Prometheus-compatible metrics |
| `/stats` | GET | Network statistics + energy model |
| `/account?addr=` | GET | Account balance and nonce |
| `/chain?from=&limit=` | GET | Block list (paginated, max 1000) |
| `/block?height=` | GET | Single block by height or hash |
| `/tx/get?hash=` | GET | Transaction lookup (confirmed/pending) |
| `/tx/proof?hash=` | GET | Merkle inclusion proof for TX |
| `/tx/pool` | GET | Mempool contents |
| `/tx/pending?addr=` | GET | Pending TXs for address |
| `/address/txs?addr=` | GET | Transaction history (paginated) |
| `/address/blocks?addr=` | GET | Blocks mined by address |
| `/bridge/locks` | GET | Bridge lock events |
| `/bridge/unlocks` | GET | Bridge unlock events |
| `/checkpoints` | GET | State checkpoints for fast sync |
| `/storage/info` | GET | Database size and stats |

### Authenticated (require X-API-Key header)
| Endpoint | Method | Description |
|----------|--------|-------------|
| `/getWork` | GET | Get mining work package |
| `/submitWork` | POST | Submit PoW solution |
| `/ws/mining` | WS | WebSocket mining (push jobs + submit) |
| `/tx/submit` | POST | Submit signed transaction |
| `/admin/prune` | POST | Trigger manual block pruning |

### P2P (port 8081)
| Endpoint | Method | Description |
|----------|--------|-------------|
| `/peer/status` | GET | Node status for heartbeat/discovery |
| `/peer/blocks?from=&to=` | GET | Serve blocks for chain sync |
| `/peer/block` | POST | Receive block from peer |
| `/peer/tx` | POST | Receive transaction from peer |
| `/peers/add?addr=` | GET | Register new peer |
| `/peers/list` | GET | List known peers with status |

---

## CLI

```
boson-cli status           Node health check
boson-cli stats            Network statistics
boson-cli balance <addr>   Account balance
boson-cli block <height>   View block details
boson-cli tx <hash>        View transaction
boson-cli history <addr>   Transaction history
boson-cli mempool          Mempool contents
boson-cli peers            Connected peers
boson-cli metrics          Raw Prometheus metrics
boson-cli version          Version info
```

---

## Configuration

See `boson.env.example` for all options. Key settings:

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `BOSON_API_KEY` | Yes | — | 64-char hex API key for miner auth |
| `BOSON_TREASURY_ADDR` | Yes | — | 40-char hex treasury address |
| `BOSON_P2P_TOKEN` | No | — | P2P auth token (production) |
| `BOSON_SEED_NODES` | No | — | Comma-separated seed node URLs |
| `BOSON_RPC_PORT` | No | 8080 | RPC API port |
| `BOSON_P2P_PORT` | No | 8081 | P2P port |
| `BOSON_DATA_DIR` | No | `.` | Data directory |
| `BOSON_WALLET_PASS` | No | — | Wallet encryption passphrase |
| `BOSON_TLS_CERT` | No | — | TLS certificate file |
| `BOSON_TLS_KEY` | No | — | TLS private key file |
| `BOSON_DEBUG` | No | — | Enable debug logging |

---

## Proof of Authorship

The original Boson Infinity blockchain protocol and reference implementation were created by **Kamil Padula** in **2025**.

This repository's commit history and timestamps provide **public, cryptographic proof of authorship and development timeline**.

The genesis block includes an embedded signed message verifying the origin of the chain and its creator.

---

## License

MIT License with protected trademark usage.
See the `LICENSE` file for details.
