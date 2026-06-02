# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

**qbtc** is a Cosmos SDK blockchain that lets Bitcoin holders claim tokens by proving ownership of their Bitcoin addresses using zero-knowledge proofs (PLONK). It supports P2PKH and P2WPKH Bitcoin addresses. The ZK approach is TSS/MPC-compatible — users only need a signature (r, s, pubkey), not direct private key access.

## Commands

### Build

```bash
# Build all binaries (qbtcd, utxo-indexer)
make build

# Install qbtcd to $GOPATH/bin
make install

# Build zkprover CLI only
make build-prover

# Build proof-service HTTP wrapper
make build-proof-service

# Build Docker image for proof-service
make docker-build-proof-service

# Run proof-service in Docker (exposes :8090)
make docker-run-proof-service

# Build Docker image for local development
make docker-localnet
```

### Testing

```bash
# Run unit tests (excludes ZK circuit tests)
make test-unit

# Run all tests including ZK (requires trusted setup)
make test-all

# Run ZK-specific tests
make test-zk

# Run tests with race condition detection
make test-race

# Run tests with coverage report (generates HTML)
make test-cover

# Run benchmarks
make bench

# Run go vet
make govet

# Run go vet + unit tests
make test

# Run vulnerability check
make govulncheck

# Run a single test
go test ./x/qbtc/zk/... -run TestFoo -v -tags testing
```

### Linting

```bash
# Run linter
make lint

# Run linter and auto-fix issues
make lint-fix

# Run markdown linter
make lint-md

# Run markdown linter and auto-fix
make lint-md-fix

# Full check: proto format + lint + markdown lint
make check
```

### Protobuf

```bash
# Generate protobuf Go files
make proto-gen

# Generate OpenAPI spec
make proto-openapi-gen

# Format proto files (requires Docker)
make proto-format

# Check proto formatting (requires Docker)
make proto-format-check

# Lint proto files (requires Docker)
make proto-lint
```

### ZK / Prover

```bash
# Generate trusted setup (Hermez PoT ceremony) — run build-prover first
make setup-prover
```

### Local Node

```bash
# Start a local node
./scripts/start-node.sh

# Generate testnet config files (requires BITCOIN_RPC_* env vars)
make generate-testnet
```

### Release

```bash
# Build release binaries locally via Docker (snapshot, no publish)
make release-local

# Publish a release via Docker (requires GITHUB_TOKEN)
make release
```

**Note**: ZK circuit tests require the `-tags testing` build tag and a pre-generated trusted setup. Use `make test-unit` for fast iteration without ZK tests.

## Architecture

### System Flow

```
Off-chain:
  TSS/MPC Signer → ECDSA signature
  zkprover CLI   → PLONK proof (hides sig & pubkey)
                          ↓
On-chain (x/qbtc module):
  MsgClaimWithProof → ZK Verifier → BankKeeper.MintCoins
                                  → mark UTXO as claimed
Background (in each validator):
  In-node observer → builds minimal UTXO delta → ABCI vote extension (digest)
                   → proposer injects once >2/3 attest → delta applied to UTXO set
```

### Key Packages

| Package | Role |
|---|---|
| `app/` | Cosmos SDK app wiring; all module keepers connected here |
| `x/qbtc/keeper/` | Core state: UTXOs, claims, ZK verifying key; handles `MsgClaimWithProof` |
| `x/qbtc/zk/` | ZK proof system: five circuits, PLONK verifier, trusted setup |
| `x/qbtc/ebifrost/` | Embedded Bitcoin observer + ABCI vote-extension handlers; builds minimal UTXO deltas |
| `bitcoin/` | Bitcoin RPC client (block/UTXO fetch) |
| `cmd/zkprover/` | CLI tool users run to generate proofs locally |
| `cmd/proof-service/` | HTTP service wrapper around zkprover for remote proof generation |

### ZK Circuit Design

`BTCPubKeyOwnershipCircuit` in `x/qbtc/zk/` proves P2PKH / P2WPKH ownership via ECDSA secp256k1 + Hash160. It uses **PLONK + KZG commitments on BN254**. The trusted setup uses Hermez/Polygon Powers of Tau (production-grade). Proofs are bound to `(destination address, chain ID, version)` to prevent replay and front-running.

The ZK verifying key is loaded at genesis init and stored immutably in chain state — it cannot be replaced post-genesis.

### Bitcoin observation (vote extensions)

Each validator's `qbtcd` observes Bitcoin directly via its configured RPC endpoint (`x/qbtc/ebifrost/`), builds a minimal UTXO delta per block, and attests the delta's digest through ABCI 2.0 vote extensions. The proposer injects the agreed delta once a >2/3 supermajority has attested it, and it is applied to the UTXO set during block execution. There is no separate daemon and no gossip network; Bitcoin RPC is configured in `app.toml [ebifrost]`.

### Claim Message Flow

`MsgClaimWithProof` →
1. `ValidateBasic()` — syntax checks
2. `zk.Verifier.VerifyProof()` — PLONK verification against stored VK
3. `Keeper.Utxoes.Get()` — look up UTXO(s) and check `EntitledAmount > 0`
4. `BankKeeper.MintCoins()` — mint to claimer's address
5. Set `EntitledAmount = 0` on the UTXO (idempotency guard)

### Dependencies

Uses btcq-org forks of `cosmos-sdk`, `cometbft`, and `wasmd` for IBC v10 / CosmWasm compatibility. See `go.mod` for exact versions. Go 1.25+ required.

## Further Reading

- `docs/ZK_SYSTEM.md` — detailed ZK circuit spec, constraint counts, and security model
- `genesis.md` — genesis configuration
