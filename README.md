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
* **Minimal Layer-0 architecture**
  (no EVM, no smart contracts, no external dependencies beyond BBolt)
* **Fully transparent math and consensus rules**
* **No hidden mechanics, no discretionary minting**

---

## Architecture

```
cmd/node/     — Node binary (RPC + P2P + Mining)
cmd/wallet/   — Desktop wallet with Argon2id encryption
cmd/cli/      — Command-line interface
core/         — Types, config, consensus parameters
crypto/       — SHA-512 hashing, DAG PoW, Ed25519 signatures
consensus/    — Rewards, difficulty retarget, block/TX validation
storage/      — BBolt database (blocks, state, TX index)
mempool/      — Indexed mempool with O(1) lookup, fee-priority
p2p/          — Peer discovery, chain sync, fork resolution
rpc/          — HTTP API, WebSocket mining, block explorer
security/     — Rate limiting, API auth, CORS, headers
```

## Quick Start

```bash
# Build
go build -o boson-node ./cmd/node/
go build -o boson-cli ./cmd/cli/
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
# Navigate to http://localhost:8080/explorer
```

## API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/health` | GET | Node health check |
| `/explorer` | GET | Built-in block explorer UI |
| `/metrics` | GET | Prometheus-compatible metrics |
| `/stats` | GET | Network statistics |
| `/getWork` | GET | Get mining work |
| `/submitWork` | POST | Submit PoW solution |
| `/ws/mining` | WS | WebSocket mining (push jobs) |
| `/tx/submit` | POST | Submit transaction |
| `/tx/get?hash=` | GET | Transaction lookup |
| `/tx/pool` | GET | Mempool contents |
| `/tx/pending?addr=` | GET | Pending TXs for address |
| `/account?addr=` | GET | Account balance |
| `/address/txs?addr=` | GET | Transaction history |
| `/address/blocks?addr=` | GET | Mined blocks |
| `/chain?from=&limit=` | GET | Block list (paginated) |
| `/block?height=` | GET | Single block |
| `/bridge/locks` | GET | Bridge lock events |
| `/bridge/unlocks` | GET | Bridge unlock events |

## CLI Commands

```
boson-cli status          — Node health check
boson-cli stats           — Network statistics
boson-cli balance <addr>  — Account balance
boson-cli block <height>  — View block
boson-cli tx <hash>       — View transaction
boson-cli history <addr>  — Transaction history
boson-cli mempool         — Mempool contents
boson-cli peers           — Connected peers
boson-cli metrics         — Prometheus metrics
```

## Mining

Miners connect via HTTP polling (`/getWork` + `/submitWork`) or **WebSocket** (`/ws/mining`) for push-based job delivery.

The PoW algorithm uses SHA-512 with a memory-hard DAG component (similar to Ethash). DAG size starts at 256MB and grows 8MB per epoch (30000 blocks).

Share difficulty support enables pool-style mining with lower difficulty submissions.

---

## Proof of Authorship

The original Boson Infinity blockchain protocol and reference implementation were created by **Kamil Padula** in **2025**.

This repository's commit history and timestamps provide **public, cryptographic proof of authorship and development timeline**.

The genesis block includes an embedded signed message verifying the origin of the chain and its creator.

---

## License

MIT License with protected trademark usage.
See the `LICENSE` file for details.
