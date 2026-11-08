# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

**qbtc** is a Cosmos SDK blockchain that lets Bitcoin holders claim tokens by proving ownership of their Bitcoin addresses using zero-knowledge proofs (PLONK). It supports P2PKH and P2WPKH Bitcoin addresses. The user signs a BIP-137 "Bitcoin Signed Message" in any wallet (or a TSS/MPC signer signs its digest); the proof hides the signature and public key.

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
  Wallet or TSS  → BIP-137 signature of "qbtc-claim-v1|<chain-id>|<btc addr>|<qbtc dest>[|<referrer>]"
  zkprover CLI   → recovers pubkey, PLONK proof (hides sig & pubkey), MsgClaimWithProof JSON
                          ↓
On-chain (x/qbtc module):
  MsgClaimWithProof → ZK Verifier → BankKeeper.MintCoins
                                  → mark UTXO as claimed
                                  → pay referral rewards from the referral pool (optional referrer)
Background:
  qbtcd (in-process Bitcoin reader) → vote extensions → proposer injects attested blocks → indexes UTXOs
```

### Key Packages

| Package | Role |
|---|---|
| `app/` | Cosmos SDK app wiring; all module keepers connected here |
| `x/qbtc/keeper/` | Core state: UTXOs, claims, ZK verifying key; handles `MsgClaimWithProof` |
| `x/qbtc/zk/` | ZK proof system: ownership circuit, BIP-137 claim message, PLONK verifier, trusted setup |
| `x/qbtc/btcreader/` | In-process Bitcoin reader and vote-extension handling inside the validator node |
| `bitcoin/` | Bitcoin RPC client for UTXO indexing |
| `cmd/zkprover/` | CLI tool users run to generate proofs locally |
| `cmd/proof-service/` | HTTP service wrapper around zkprover for remote proof generation |

### ZK Circuit Design

`BTCPubKeyOwnershipCircuit` in `x/qbtc/zk/` proves P2PKH / P2WPKH ownership via ECDSA secp256k1 + Hash160. It uses **PLONK + KZG commitments on BN254**. The trusted setup uses Hermez/Polygon Powers of Tau (production-grade). The signed message is the BIP-137 digest of `qbtc-claim-v1|<chain-id>|<bitcoin address>|<destination>[|<referrer>]` (the referrer field is left out when there is none), derived natively by both prover and verifier, so proofs are bound to the chain, the address, the destination and the referrer without the circuit knowing the format.

The ZK verifying key is loaded at genesis init and stored immutably in chain state — it cannot be replaced post-genesis.

### Bitcoin Block Ingestion

Each validator's `qbtcd` reads Bitcoin from its own Bitcoin node through an in-process reader configured in the `[btc_reader]` section of `app.toml` (`enable`, `bitcoin_host`, `bitcoin_port`, `bitcoin_rpc_user`, `bitcoin_rpc_password`, `confirmation_depth` default 6). Validators attest blocks in ABCI vote extensions; the next proposer injects blocks attested by more than 2/3 of the voting power, together with the signed votes as evidence. There is no separate bifrost daemon and no P2P gossip.

### Claim Message Flow

`MsgClaimWithProof` →
1. `ValidateBasic()` — syntax checks
2. `Keeper.Utxoes.Get()` — look up the first claimable UTXO for its Bitcoin address string
3. `zk.Verifier.VerifyProof()` — rebuild the claim digest from (chain ID, address, receiver-or-claimer, referrer), check `RIPEMD160(pub_key_hash_sha256)` against the address, PLONK verification against stored VK
4. `BankKeeper.MintCoins()` — mint to claimer's address
5. Set `EntitledAmount = 0` on the UTXO (idempotency guard) and record its referrer
6. If a referrer is set, pay `ReferrerRewardBps` / `RefereeRewardBps` of the claimed amount from the `referral` module account (capped at its balance, never fails the claim) and update `ReferralStats`

### Dependencies

Upstream `cosmos-sdk` v0.55 and `cometbft` v0.40, no forks. See `go.mod` for exact versions. Go 1.26.5+ required.

The chain accepts **ML-DSA-65 keys only**, for validator consensus keys (`consensus_params.validator.pub_key_types = ["ml_dsa_65"]`, checked by staking, by CometBFT and at InitChain by `app/genesis_guard.go`) and for account keys (`app/sig_gas_consumer.go` rejects every other pubkey type, including multisig; the CLI keyring only creates `ml_dsa_65` keys). `qbtcd init` and `qbtcd keys add` default to it.

CosmWasm, IBC and tokenfactory are not wired in v1. They are planned to be added later through a governance software upgrade (see `app/upgrades.go`) once wasmd and ibc-go release on SDK v0.55.

## Further Reading

- `docs/ZK_SYSTEM.md` — detailed ZK circuit spec, constraint counts, and security model
- `genesis.md` — genesis configuration
