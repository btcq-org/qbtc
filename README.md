# qbtc

**qbtc** is a blockchain built using Cosmos SDK and CometBFT that enables Bitcoin holders to claim tokens by proving ownership of their Bitcoin addresses using zero-knowledge proofs.

## Features

- **Zero-Knowledge Proof Verification**: Claim Bitcoin UTXOs without revealing private keys or signatures
- **Multi-Script Support**: Supports all major Bitcoin address types
- **TSS/MPC Compatible**: Works with threshold signature schemes
- **Front-running Protection**: Proofs are bound to destination addresses
- **Cross-chain Replay Protection**: Proofs are bound to chain ID

## Supported Bitcoin Address Types

| Address Type | Format | Status |
|--------------|--------|--------|
| P2PKH | `1...` | ✅ Supported |
| P2WPKH (Native SegWit) | `bc1q...` (42 chars) | ✅ Supported |

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                         USER DOMAIN                              │
├─────────────────────────────────────────────────────────────────┤
│  TSS/MPC Signer  ──▶  zkprover CLI  ──▶  PLONK Proof            │
│                       (hides signature)                          │
└───────────────────────────────┬─────────────────────────────────┘
                                │
                                ▼ Submit MsgClaimWithProof
┌─────────────────────────────────────────────────────────────────┐
│                         CHAIN DOMAIN                             │
├─────────────────────────────────────────────────────────────────┤
│  Keeper Handler  ──▶  ZK Verifier  ──▶  Mint Tokens             │
└─────────────────────────────────────────────────────────────────┘
```

## Getting Started

### Prerequisites

- Go 1.22+
- Make

### Build

```bash
make build
```

### Run Tests

```bash
# Run all tests
make test

# Run ZK-specific tests
go test -tags=testing ./x/qbtc/zk/...
```

### Start a Local Node

```bash
./scripts/start-node.sh
```

### Start a 4-Validator Network

`make localnet` runs four validators in Docker ([docker-compose.yml](docker-compose.yml)) that follow Bitcoin mainnet, from your own Bitcoin node or, without one, through a proxy over a public Esplora API:

```bash
make localnet                                  # public API (mempool.space), starts a few blocks below the tip
BITCOIN_RPC_HOST=localhost BITCOIN_RPC_PORT=8332 BITCOIN_RPC_USER=u BITCOIN_RPC_PASSWORD=p make localnet
GENESIS_BIN=~/genesis-931372.bin BTC_INITIAL_HEIGHT=931373 make localnet   # with a UTXO snapshot
make localnet-status                           # chain height and last processed Bitcoin block per validator
make localnet-down                             # stop, keep .testnets/
make localnet-clean                            # stop and delete .testnets/
```

Validator `i` listens on CometBFT RPC `26657-3i`, REST `1317-i` and gRPC `9090-2i` (move a taken host port with `RPC_PORT_i`, `API_PORT_i` or `GRPC_PORT_i`, e.g. `API_PORT_0=11317 make localnet`); the state lives in `.testnets/`. The image is built with `make docker-localnet` when missing. `scripts/localnet.sh` lists every option.

## Running a Node

Use the install script to set up a qbtc node on a server:

```bash
curl -sSL https://raw.githubusercontent.com/btcq-org/qbtc/main/scripts/install.sh | bash
```

The script will guide you through:

1. **Installing binaries** - Downloads `qbtcd` to `/usr/local/bin`
2. **Cosmovisor setup** - Optional for managed upgrades
3. **Node initialization** - Creates config directory and downloads genesis file
4. **Systemd service** - Sets up a service for automatic startup and management

### Manual Installation

If you prefer to install manually or need a specific version:

```bash
# Download specific version
curl -sSL https://raw.githubusercontent.com/btcq-org/qbtc/main/scripts/install.sh | bash -s -- -v 1.0.7

# Or set version via environment variable
QBTC_VERSION=1.0.7 bash -c "$(curl -sSL https://raw.githubusercontent.com/btcq-org/qbtc/main/scripts/install.sh)"
```

### Post-Installation

After installation, configure your node:

1. Point qbtcd at your own Bitcoin node in the `[btc_reader]` section of `~/.qbtc/config/app.toml`:
   ```toml
   [btc_reader]
   enable = true
   bitcoin_host = "127.0.0.1"
   bitcoin_port = 8332
   bitcoin_rpc_user = "bitcoinrpc"
   bitcoin_rpc_password = "securepassword"
   confirmation_depth = 6
   ```
   Each validator's qbtcd reads Bitcoin through this in-process reader and attests blocks in ABCI vote extensions. The next proposer injects blocks attested by more than 2/3 of the voting power, together with the signed votes as evidence.

2. Start the service:
   ```bash
   sudo systemctl start qbtcd
   ```

3. Check status:
   ```bash
   sudo systemctl status qbtcd
   sudo journalctl -u qbtcd -f
   ```

## Documentation

- [ZK Proof System Technical Specification](docs/ZK_SYSTEM.md) - Detailed documentation of the zero-knowledge proof system

## Project Structure

```
qbtc/
├── app/                    # Cosmos SDK application
├── bitcoin/               # Bitcoin indexer
├── cmd/
│   ├── qbtcd/            # Main chain daemon
│   ├── zkprover/         # ZK proof generation CLI
│   └── tss-emulator/     # TSS signer emulator for testing
├── common/                # Shared types and utilities
├── constants/             # Chain constants
├── docs/                  # Documentation
├── proto/                 # Protocol buffer definitions
├── scripts/               # Utility scripts
├── testdata/              # Test fixtures
├── testutil/              # Test utilities
└── x/
    └── qbtc/
        ├── keeper/       # State management
        ├── module/       # Cosmos module definition
        ├── types/        # Type definitions
        └── zk/           # Zero-knowledge proof system
```

## ZK Proof System

The ZK system uses PLONK proofs with KZG commitments to verify Bitcoin address ownership:

- **Proof System**: PLONK with BN254 pairing curve
- **Signature Scheme**: ECDSA (secp256k1)
- **Hash Functions**: SHA-256, RIPEMD-160
- **Trusted Setup**: Hermez/Polygon Powers of Tau ceremony

### Circuit

| Circuit | Script Types | Signature |
|---------|--------------|-----------|
| `BTCPubKeyOwnershipCircuit` | P2PKH, P2WPKH | ECDSA |

## Security

The ZK system has been audited for:

- **Soundness**: Invalid proofs are rejected
- **Zero-Knowledge**: Signatures and keys remain private
- **Binding**: Proofs are bound to address, destination, and chain
- **Immutability**: Verifier keys cannot be replaced after initialization

See [Security Audit Results](docs/ZK_SYSTEM.md#13-security-audit-results) for details.

## License

[License information here]
