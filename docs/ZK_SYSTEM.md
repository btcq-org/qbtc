# ZK Proof System Documentation

## Overview
The qbtc ZK proof system enables users to claim UTXOs by proving ownership of a Bitcoin address without revealing their private or public key. It uses the PLONK proof system with KZG commitments to generate zero-knowledge proofs that are verified on-chain.

## Claim Pathways

Users have two methods to claim their entitled tokens from a UTXO. Both pathways use the unified `ClaimUTXO` function.

### 1. On-Chain Bitcoin Transaction (Standard Claim)
- User sends a Bitcoin transaction **to themselves** with an `OP_RETURN` output containing `claim:{btcq_address}`.
- Bifrost nodes observe this transaction via `MsgReportBlock`.
- The `processClaimTx` function validates and calls `ClaimUTXO`.
- **Pros**: Simple, uses standard Bitcoin tooling.
- **Cons**: Requires on-chain BTC transaction (fees), exposes public key.

### 2. ZK Proof Claim (`MsgClaimWithProof`)
- User generates a ZK proof offline using the `zkprover` CLI.
- User submits `MsgClaimWithProof` directly to the qbtc chain.
- The proof demonstrates ownership of the Bitcoin address without revealing the private key.
- **Pros**: No Bitcoin transaction required, private key never exposed, saves BTC fees.
- **Cons**: Requires generating a ZK proof (~4-8GB RAM).

### 3. Governance Reclaim (`MsgGovClaimUTXO`)
- Used by governance to reclaim **unclaimed UTXOs** to the reserve module.
- Calls `ClaimUTXO` with `nil` recipient (mints to reserve).
- Not for user claims.

### Unified Claim Logic (`ClaimUTXO`)

All claim pathways call `ClaimUTXO(ctx, txid, vout, recipient)`:
1. Looks up the UTXO by `txid:vout`.
2. If `EntitledAmount == 0`, returns (already claimed).
3. Mints `EntitledAmount` tokens:
   - If `recipient != nil`: Mints to user via module account.
   - If `recipient == nil`: Mints to reserve module (governance reclaim).
4. Sets `EntitledAmount = 0` to prevent double-claiming.

## System Specifications
- **Proof System**: PLONK (with KZG commitments)
- **Curve**: BN254 (also known as BN128)
- **Constraint System**: SCS (Sparse Constraint System for PLONK)
- **Library**: [gnark](https://github.com/ConsenSys/gnark)
- **Trusted Setup**: Requires a structured reference string (SRS).
  - **Production**: Uses the **Hermez/Polygon Powers of Tau** ceremony (Power 20, ~1M constraints).
  - **Development**: Can use insecure test SRS (via `--test` flag).

## Circuit Logic (`BTCAddressCircuit`)
The circuit proves knowledge of a Bitcoin private key that corresponds to a public Bitcoin address (Hash160).

### Inputs
| Type | Name | Description |
|------|------|-------------|
| **Private** | `PrivateKey` | Bitcoin private key (secp256k1 scalar, 256 bits). |
| **Public** | `AddressHash` | Hash160 (RIPEMD160(SHA256(pubkey))) of the Bitcoin address (20 bytes). |
| **Public** | `BTCQAddressHash` | SHA256 of the destination qbtc address (32 bytes). |
| **Public** | `ChainID` | First 8 bytes of SHA256(chain_id). |

### Constraints & Verification
1.  **Key Derivation**: Computes `PublicKey = PrivateKey * G` using emulated secp256k1 arithmetic.
2.  **Compression**: Compresses the public key (33 bytes with 0x02/0x03 prefix).
3.  **Hashing**: Computes `Hash160 = RIPEMD160(SHA256(CompressedPublicKey))`.
4.  **Assertion**: Enforces `ComputedHash160 == AddressHash`.
5.  **Binding**: The proof is cryptographically bound to the `BTCQAddressHash` and `ChainID` via PLONK's public input mechanism.

## MsgClaimWithProof Flow

### Message Structure

```protobuf
message MsgClaimWithProof {
  string claimer = 1;           // qbtc address to receive tokens
  repeated UTXORef utxos = 2;   // List of UTXOs to claim (max 50)
  ZKProof proof = 3;            // Single ZK proof for the Bitcoin address
}

message UTXORef {
  string txid = 1;  // Bitcoin transaction ID (64 hex chars)
  uint32 vout = 2;  // Output index
}
```

### Batch Claiming

Users can claim **up to 50 UTXOs** in a single transaction, provided:
- All UTXOs belong to the **same Bitcoin address**.
- A single ZK proof proves ownership of that address.

This is efficient for users with multiple UTXOs from the same wallet.

### Handler Logic

1. User provides:
   - `claimer`: Their qbtc address (receives the tokens).
   - `utxos`: List of `{txid, vout}` pairs to claim.
   - `proof`: The ZK proof data.

2. Validation (`ValidateBasic`):
   - `claimer` is a valid bech32 address.
   - At least 1 UTXO, at most 50 UTXOs.
   - Each UTXO has a valid 64-character hex txid.
   - No duplicate UTXOs in the batch.
   - Proof size: min 100 bytes, max 50KB.

3. Handler Validation:
   - All UTXOs must exist and have `EntitledAmount > 0`.
   - All UTXOs must belong to the **same Bitcoin address**.
   - The ZK proof must be valid for that address.

4. Execution (atomic):
   - If proof is valid, all UTXOs are claimed atomically using cache context.
   - Total amount is minted to the `claimer` address.
   - Each UTXO's `EntitledAmount` is set to 0.

5. If any UTXO fails validation, the entire batch is rejected.

## Security Assumptions & Features

### 1. Trusted Setup
Relies on the security of the Hermez Powers of Tau ceremony. As long as one participant was honest, the setup is secure. The SRS is downloaded from `https://hermez.s3-eu-west-1.amazonaws.com/powersOfTau28_hez_final_XX.ptau`.

### 2. Front-Running Protection
The proof includes the recipient's qbtc address (`BTCQAddressHash`) as a public input. Only the designated recipient can use the proof. If an attacker intercepts the proof, they cannot redirect funds to their own address.

### 3. Replay Protection
- **Cross-Chain**: The `ChainID` public input (first 8 bytes of SHA256(chain_id)) prevents proofs from being replayed on other chains (e.g., testnet vs mainnet).
- **On-Chain**: `ClaimUTXO` sets `EntitledAmount = 0` after claiming, preventing double-spending.

### 4. UTXO Binding
The user specifies which UTXO (`txid:vout`) they are claiming. The proof is verified against the address locked in that specific UTXO, not just any address.

### 5. Verifier Immutability
The global verifier can only be initialized once at node startup. Subsequent calls to `RegisterVerifier` return `ErrVerifierAlreadyInitialized`, preventing malicious VK replacement attacks.

### 6. Memory Security
The `zkprover` CLI securely clears private key material from memory after use:
- `big.Int` values are zeroed via `SetInt64(0)`.
- Byte slices are explicitly zeroed.
- Interactive stdin mode (`--stdin`) prevents keys from appearing in shell history.

## Requirements

### Prover (User)
- `zkprover` CLI tool
- Access to `proving.key` and `circuit.cs` files (generated via `zkprover setup`)
- Sufficient RAM to hold the SRS and circuit witness (~4-8GB)

### Verifier (On-Chain)
- `verifying.key` must be embedded in chain genesis as `zk_verifying_key` (hex-encoded)
- Lightweight verification (constant time/size with KZG)
- Verifying key is registered once at node startup from genesis

## Usage

### 1. Setup (One-Time)

Generate the proving and verifying keys:

```bash
# Production setup (uses Hermez ceremony SRS)
zkprover setup --output ./zk-setup

# Development/testing only (UNSAFE - do not use in production!)
zkprover setup --output ./zk-setup --test
```

Output files:
- `circuit.cs` - Compiled constraint system
- `proving.key` - Used for proof generation
- `verifying.key` - Binary format for embedding
- `verifying.key.hex` - Hex format for genesis.json

### 2. Generate Proof

```bash
# Recommended: Interactive mode (secure)
zkprover prove --stdin \
  --btcq-address qbtc1... \
  --chain-id qbtc-1 \
  --setup-dir ./zk-setup \
  --output proof.json

# Alternative: Direct key input (less secure)
zkprover prove \
  --private-key <hex> \
  --btcq-address qbtc1... \
  --chain-id qbtc-1 \
  --setup-dir ./zk-setup
```

Output format:
```json
{
  "btc_address_hash": "abc123...",
  "btcq_address": "qbtc1...",
  "chain_id": "qbtc-1",
  "proof_data": "..."
}
```

### 3. Address Utilities

```bash
# Get address hash from private key
zkprover address from-key --private-key <hex>
zkprover address from-key --wif <wif>

# Extract address hash from Bitcoin address (P2PKH/P2WPKH)
zkprover address from-address --address bc1q...
```

### 4. Submit Claim

Submit `MsgClaimWithProof` to the chain with:
- `claimer`: Your qbtc address
- `utxos`: Array of `{txid, vout}` pairs
- `proof`: The proof data from step 2

The node verifies the proof against the embedded verifying key and the UTXO's address, then mints tokens to the claimer.

## Proof Format

The proof is serialized as:
```
[4 bytes: proof length (big-endian)] [proof data] [public inputs]
```

- Proof data: PLONK proof (~1KB)
- Public inputs: Serialized witness values for verification

Size limits:
- Minimum: 100 bytes
- Maximum: 50KB (message level), 1MB (internal parsing)
