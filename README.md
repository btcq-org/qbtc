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

## Running a Node

Use the install script to set up a qbtc node on a server:

```bash
curl -sSL https://raw.githubusercontent.com/btcq-org/qbtc/main/scripts/install.sh | bash
```

The script will guide you through:

1. **Installing binaries** - Downloads `qbtcd` and `bifrost` to `/usr/local/bin`
2. **Cosmovisor setup** - Optional for managed upgrades
3. **Node initialization** - Creates config directory and downloads genesis file
4. **Bifrost configuration** - Creates config template for the enshrined service.
5. **Systemd services** - Sets up services for automatic startup and management

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

1. Edit bifrost config with your Bitcoin RPC credentials:
   ```bash
   vim ~/.bifrost/config.json
   ```

2. Start the services:
   ```bash
   sudo systemctl start qbtcd
   sudo systemctl start bifrost
   ```

3. Check status:
   ```bash
   sudo systemctl status qbtcd bifrost
   sudo journalctl -u qbtcd -f
   ```

## Documentation

- [ZK Proof System Technical Specification](docs/ZK_SYSTEM.md) - Detailed documentation of the zero-knowledge proof system

## Project Structure

```
qbtc/
├── app/                    # Cosmos SDK application
├── bifrost/               # P2P network service
├── bitcoin/               # Bitcoin indexer
├── cmd/
│   ├── qbtcd/            # Main chain daemon
│   ├── zkprover/         # ZK proof generation CLI
│   ├── bifrost/          # Bifrost service
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
