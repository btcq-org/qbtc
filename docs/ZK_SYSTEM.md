# ZK Proof System Documentation

## Overview

The qbtc ZK proof system enables users to claim UTXOs by proving ownership of a Bitcoin address without revealing the private key, public key, or signature. It uses PLONK with KZG commitments and is designed for **TSS/MPC compatibility** - only a signature is required, not direct key access.

## Architecture

```
┌─────────────────┐     ┌──────────────┐     ┌─────────────────┐
│   TSS Signer    │────▶│   zkprover   │────▶│   BTCQ Chain    │
│  (signs msg)    │     │  (ZK proof)  │     │   (verifier)    │
└─────────────────┘     └──────────────┘     └─────────────────┘
        │                      │                     │
   Returns sig           Generates proof        Verifies proof
   + public key          (hides sig/pubkey)     (sees only hash)
```

## Circuit (`BTCSignatureCircuit`)

The circuit proves ownership using an ECDSA signature. The signature and public key remain hidden.

### Inputs

| Type | Name | Description |
|------|------|-------------|
| **Private** | `SignatureR` | ECDSA signature r scalar (x-coord of k·G mod n) |
| **Private** | `SignatureS` | ECDSA signature s scalar |
| **Private** | `PublicKeyX`, `PublicKeyY` | Public key coordinates (base field) |
| **Public** | `MessageHash` | SHA256 of the claim message (32 bytes) |
| **Public** | `AddressHash` | Hash160 of the Bitcoin address (20 bytes) |
| **Public** | `BTCQAddressHash` | SHA256 of destination qbtc address (32 bytes) |
| **Public** | `ChainID` | First 8 bytes of SHA256(chain_id) |

### Constraints

1. Verify ECDSA signature is valid for `(PublicKey, MessageHash)`
2. Compute `Hash160(compress(PublicKey))`
3. Assert computed hash equals `AddressHash`

### Message Format

The TSS signer signs this deterministic message:

```
MessageHash = SHA256(AddressHash || BTCQAddressHash || ChainID || "qbtc-claim-v1")
```

## Usage

### 1. Setup (One-Time)

```bash
# Production (uses Hermez Powers of Tau ceremony)
zkprover setup --output ./zk-setup

# Development only (UNSAFE)
zkprover setup --output ./zk-setup --test
```

Output files:
- `circuit.cs` - Constraint system
- `proving.key` - For proof generation
- `verifying.key.hex` - For genesis.json

### 2. Generate Proof

```bash
zkprover prove \
  --tss-url http://localhost:8080 \
  --address-hash <hash160_hex> \
  --btcq-address qbtc1... \
  --chain-id qbtc-1 \
  --setup-dir ./zk-setup \
  --output proof.json
```

### 3. Submit Claim

Submit `MsgClaimWithProof` with:
- `claimer`: Your qbtc address
- `utxos`: Array of `{txid, vout}` pairs (up to 50)
- `proof`: The proof data

**Partial Claim Behavior**: Only UTXOs matching the proven Bitcoin address will be claimed. UTXOs that don't match (different address, already claimed, not found) are skipped without failing the transaction. The response includes `utxos_claimed` and `utxos_skipped` counts for transparency.

## TSS API Specification

Your TSS signer must implement:

**`POST /sign`**

Request:
```json
{ "message_hash": "<64 hex chars>" }
```

Response:
```json
{
  "signature": { "r": "<hex>", "s": "<hex>", "v": 0 },
  "public_key": "<66 hex chars - compressed>"
}
```

### TSS Emulator (Testing)

```bash
tss-emulator --port :8080 --private-key <hex>
# or: TSS_PRIVATE_KEY=<hex> tss-emulator
```

Endpoints: `POST /sign`, `GET /health`, `GET /info`

## Security

| Feature | Protection |
|---------|------------|
| **Front-running** | Proof bound to `BTCQAddressHash` - only designated recipient can use it |
| **Cross-chain replay** | `ChainID` prevents reuse on other networks |
| **Double-spend** | `EntitledAmount` set to 0 after claim |
| **Key privacy** | Signature and public key are private circuit inputs |
| **Verifier immutability** | VK registered once at startup, cannot be replaced |

## Specifications

- **Proof System**: PLONK with KZG commitments
- **Curve**: BN254
- **Library**: [gnark](https://github.com/ConsenSys/gnark)
- **Trusted Setup**: Hermez/Polygon Powers of Tau (Power 20)
- **Proof Size**: ~1KB
- **RAM Required**: ~4-8GB for proof generation
