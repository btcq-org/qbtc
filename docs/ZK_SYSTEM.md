# ZK Proof System Documentation

## Overview
The qbtc ZK proof system enables users to claim UTXOs by proving ownership of a Bitcoin address without revealing their private or public key. It uses the PLONK proof system to generate zero-knowledge proofs that are verified on-chain.

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
- **Constraint System**: R1CS / Sparse Constraint System (SCS)
- **Trusted Setup**: Requires a structured reference string (SRS).
  - **Production**: Uses the **Hermez/Polygon Powers of Tau** ceremony (Power 20, ~1M constraints).
  - **Development**: Can use insecure test SRS.

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
2.  **Compression**: Compresses the public key (33 bytes).
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

2. Validation:
   - All UTXOs must exist and have `EntitledAmount > 0`.
   - All UTXOs must belong to the **same Bitcoin address**.
   - The ZK proof must be valid for that address.

3. Execution (atomic):
   - If proof is valid, all UTXOs are claimed atomically.
   - Total amount is minted to the `claimer` address.
   - Each UTXO's `EntitledAmount` is set to 0.

4. If any UTXO fails validation, the entire batch is rejected.

## Security Assumptions & Features
1.  **Trusted Setup**: Relies on the security of the Hermez Powers of Tau ceremony. As long as one participant was honest, the setup is secure.
2.  **Front-Running Protection**: The proof includes the recipient's qbtc address (`BTCQAddressHash`) as a public input. Only the designated recipient can use the proof.
3.  **Replay Protection**:
    -   **Cross-Chain**: The `ChainID` public input prevents proofs from being replayed on other chains (e.g., testnet vs mainnet).
    -   **On-Chain**: `ClaimUTXO` sets `EntitledAmount = 0` after claiming, preventing double-spending.
4.  **UTXO Binding**: The user specifies which UTXO (`txid:vout`) they are claiming. The proof is verified against the address locked in that specific UTXO.

## Requirements
-   **Prover**:
    -   Requires `zkprover` CLI tool.
    -   Access to `proving.key` and `circuit.cs`.
    -   Sufficient RAM to hold the SRS and circuit witness (~4-8GB).
-   **Verifier (On-Chain)**:
    -   `verifying.key` must be embedded in the chain genesis.
    -   Lightweight verification (constant time/size with KZG).

## Usage
1.  **Setup**: Run `zkprover setup` to download SRS and generate keys.
2.  **Prove**: Run `zkprover prove` with private key, txid, vout, and destination details.
3.  **Verify**: Submit `MsgClaimWithProof` to the chain; the node verifies it against the embedded verifying key and the UTXO's address.
