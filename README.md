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
| P2TR (Taproot) | `bc1p...` | ✅ Supported |
| P2SH-P2WPKH (Wrapped SegWit) | `3...` | ✅ Supported |
| P2PK (Legacy) | Raw script | ✅ Supported |
| P2WSH (Single-key) | `bc1q...` (62 chars) | ✅ Supported |

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
- **Signature Schemes**: ECDSA (secp256k1), Schnorr (BIP-340)
- **Hash Functions**: SHA-256, RIPEMD-160, BIP-340 Tagged Hash
- **Trusted Setup**: Hermez/Polygon Powers of Tau ceremony

### Circuits

| Circuit | Script Types | Signature |
|---------|--------------|-----------|
| `BTCSignatureCircuit` | P2PKH, P2WPKH | ECDSA |
| `BTCSchnorrCircuit` | P2TR (key-path) | Schnorr |
| `BTCP2SHP2WPKHCircuit` | P2SH-P2WPKH | ECDSA |
| `BTCP2PKCircuit` | P2PK | ECDSA |
| `BTCP2WSHSingleKeyCircuit` | P2WSH (single-key) | ECDSA |

## Security

The ZK system has been audited for:

- **Soundness**: Invalid proofs are rejected
- **Zero-Knowledge**: Signatures and keys remain private
- **Binding**: Proofs are bound to address, destination, and chain
- **Immutability**: Verifier keys cannot be replaced after initialization

See [Security Audit Results](docs/ZK_SYSTEM.md#13-security-audit-results) for details.

## License

[License information here]
