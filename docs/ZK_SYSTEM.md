# ZK Proof System Technical Specification

**Version**: 2.0  
**Last Updated**: December 2025 
**Status**: Ready for Security Audit

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [System Architecture](#2-system-architecture)
3. [Cryptographic Primitives](#3-cryptographic-primitives)
4. [Circuit Design](#4-circuit-design)
5. [Message Format and Binding](#5-message-format-and-binding)
6. [Trusted Setup](#6-trusted-setup)
7. [Proof Generation](#7-proof-generation)
8. [Proof Verification](#8-proof-verification)
9. [Security Analysis](#9-security-analysis)
10. [Implementation Details](#10-implementation-details)
11. [File Reference](#11-file-reference)
12. [Supported Bitcoin Script Types](#12-supported-bitcoin-script-types)

---

## 1. Executive Summary

### 1.1 Purpose

The qbtc ZK proof system enables users to claim Bitcoin UTXOs on the qbtc chain by proving ownership of a Bitcoin address **without revealing**:
- The private key
- The public key  
- The signature (ECDSA or Schnorr)

This is achieved through PLONK zero-knowledge proofs that demonstrate knowledge of a valid signature for a specific message, where the public key corresponds to the claimed Bitcoin address.

### 1.2 Supported Bitcoin Address Types

| Address Type | Prefix | Circuit | Status |
|--------------|--------|---------|--------|
| **P2PKH** | `1...` | ECDSA | ✅ Supported |
| **P2WPKH** | `bc1q...` (short) | ECDSA | ✅ Supported |
| **P2TR (Taproot)** | `bc1p...` | Schnorr | ✅ Supported |
| **P2SH-P2WPKH** | `3...` | ECDSA | ✅ Supported |
| **P2PK** | (raw script) | ECDSA | ✅ Supported |
| **P2WSH (single-key)** | `bc1q...` (long) | ECDSA | ✅ Supported |
| **P2WSH (multisig)** | `bc1q...` (long) | - | ❌ Not Supported |
| **P2SH (arbitrary)** | `3...` | - | ❌ Not Supported |
| **P2TR (script-path)** | `bc1p...` | - | ❌ Not Supported |

### 1.3 Design Goals

| Goal | Implementation |
|------|----------------|
| **TSS/MPC Compatibility** | Only requires a signature; no private key access needed |
| **Privacy** | Signature and public key are private circuit inputs |
| **Front-running Protection** | Proof bound to destination address |
| **Replay Protection** | Chain ID and version string in signed message |
| **Double-spend Prevention** | UTXO marked as claimed after successful verification |
| **Multi-Script Support** | Dedicated circuits for each major script type |

### 1.4 Key Parameters

| Parameter | Value |
|-----------|-------|
| Proof System | PLONK with KZG commitments |
| Pairing Curve | BN254 (alt_bn128) |
| Signature Curves | secp256k1 (ECDSA), secp256k1 (Schnorr/BIP-340) |
| Hash Functions | SHA-256, RIPEMD-160, BIP-340 Tagged Hash |
| Trusted Setup | Hermez/Polygon Powers of Tau (2²¹) |
| Proof Size | ~1 KB |
| Verification Time | ~2-5 ms |

---

## 2. System Architecture

### 2.1 High-Level Flow

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              USER DOMAIN                                     │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  ┌─────────────┐    1. Sign Message    ┌──────────────┐                    │
│  │ TSS/MPC     │ ──────────────────────▶│  zkprover   │                    │
│  │ Signer      │◀────────────────────── │  CLI Tool   │                    │
│  │             │    (r, s, pubkey)      │             │                    │
│  └─────────────┘                        └──────┬──────┘                    │
│        │                                       │                            │
│        │ Never leaves                          │ 2. Generate ZK Proof      │
│        │ user's system                         │    (hides sig + pubkey)   │
│        ▼                                       ▼                            │
│   [Private Key]                         [PLONK Proof]                      │
│                                                │                            │
└────────────────────────────────────────────────┼────────────────────────────┘
                                                 │
                                                 │ 3. Submit MsgClaimWithProof
                                                 ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                              CHAIN DOMAIN                                    │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  ┌──────────────┐    4. Verify Proof    ┌──────────────┐                   │
│  │  Keeper      │ ─────────────────────▶│  Verifier    │                   │
│  │  Handler     │◀───────────────────── │  (Global VK) │                   │
│  │              │      valid/invalid    │              │                   │
│  └──────┬───────┘                       └──────────────┘                   │
│         │                                                                   │
│         │ 5. If valid: mint tokens to claimer                              │
│         ▼                                                                   │
│  ┌──────────────┐                                                          │
│  │  Bank Module │  Mark UTXO.EntitledAmount = 0                            │
│  └──────────────┘                                                          │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

### 2.2 Data Flow

1. **Message Construction**: User computes claim message hash from Bitcoin address hash, destination qbtc address hash, chain ID hash, and version string

2. **Signature**: TSS/MPC system signs the message hash with ECDSA on secp256k1

3. **Proof Generation**: zkprover creates PLONK proof with private inputs (signature, public key) and public inputs (message hash, address hash, btcq address hash, chain ID)

4. **On-chain Verification**: Handler verifies proof against expected public inputs

5. **Claim Execution**: Tokens minted to claimer, UTXO marked as claimed

---

## 3. Cryptographic Primitives

### 3.1 Elliptic Curves

#### secp256k1 (Bitcoin/ECDSA)
- **Base Field (Fp)**: p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
- **Scalar Field (Fr)**: n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
- **Generator**: Standard secp256k1 generator point G
- **Cofactor**: 1

#### BN254 (Proof System)
- Used for PLONK pairings
- ~128-bit security level
- Efficient for on-chain verification

### 3.2 Hash Functions

#### SHA-256
- **In-circuit**: gnark's `std/hash/sha2` gadget
- **Used for**: Message hash computation, address hash binding

#### RIPEMD-160
- **In-circuit**: Custom implementation following the RIPEMD-160 specification
- **Used for**: Bitcoin address computation (Hash160 = RIPEMD160(SHA256(pubkey)))

### 3.3 ECDSA Signature Scheme

The circuit verifies standard ECDSA signatures:

Given:
- Message hash `z` ∈ Fr
- Signature `(r, s)` where r, s ∈ Fr
- Public key `P` ∈ E(Fp)

Verification computes:
```
u₁ = z · s⁻¹ mod n
u₂ = r · s⁻¹ mod n
R' = u₁·G + u₂·P
```

Signature is valid iff `R'.x mod n = r`

**Implementation**: Uses gnark's `std/signature/ecdsa` gadget with emulated arithmetic for secp256k1 over BN254.

---

## 4. Circuit Design

The ZK system implements multiple specialized circuits for different Bitcoin script types. Each circuit is optimized for its specific verification requirements.

### 4.1 Circuit Overview

| Circuit | File | Script Types | Signature |
|---------|------|--------------|-----------|
| `BTCSignatureCircuit` | `circuit_signature.go` | P2PKH, P2WPKH | ECDSA |
| `BTCSchnorrCircuit` | `circuit_schnorr.go` | P2TR (key-path) | Schnorr/BIP-340 |
| `BTCP2SHP2WPKHCircuit` | `circuit_p2sh_p2wpkh.go` | P2SH-P2WPKH | ECDSA |
| `BTCP2PKCircuit` | `circuit_p2pk.go` | P2PK (legacy) | ECDSA |
| `BTCP2WSHSingleKeyCircuit` | `circuit_p2wsh_single_key.go` | P2WSH (single-key) | ECDSA |

### 4.2 ECDSA Circuit (P2PKH/P2WPKH)

**File**: `x/qbtc/zk/circuit_signature.go`

The `BTCSignatureCircuit` handles standard Bitcoin addresses:

**Private Inputs** (hidden in proof):
| Field | Type | Description |
|-------|------|-------------|
| `SignatureR` | Secp256k1Fr | ECDSA r scalar (x-coord of k·G mod n) |
| `SignatureS` | Secp256k1Fr | ECDSA s scalar |
| `PublicKeyX` | Secp256k1Fp | Public key X coordinate |
| `PublicKeyY` | Secp256k1Fp | Public key Y coordinate |

**Public Inputs** (visible to verifier):
| Field | Size | Description |
|-------|------|-------------|
| `MessageHash` | 32 bytes | SHA256 of the claim message |
| `AddressHash` | 20 bytes | Hash160 of Bitcoin public key |
| `BTCQAddressHash` | 32 bytes | SHA256 of destination qbtc address |
| `ChainID` | 8 bytes | First 8 bytes of SHA256(chain_id) |

**Constraints**:
1. ECDSA signature verification (gnark standard gadget)
2. Public key compression to SEC1 format
3. Hash160(compressed_pubkey) == AddressHash

### 4.3 Schnorr Circuit (P2TR/Taproot)

**File**: `x/qbtc/zk/circuit_schnorr.go`

The `BTCSchnorrCircuit` handles Taproot key-path spending with BIP-340 Schnorr signatures:

**Private Inputs**:
| Field | Type | Description |
|-------|------|-------------|
| `SignatureR` | Secp256k1Fr | Nonce point R x-coordinate |
| `SignatureS` | Secp256k1Fr | s scalar |
| `PublicKeyX` | Secp256k1Fp | Public key X coordinate |
| `PublicKeyY` | Secp256k1Fp | Public key Y (must have even parity) |

**Public Inputs**:
| Field | Size | Description |
|-------|------|-------------|
| `MessageHash` | 32 bytes | SHA256 of the claim message |
| `XOnlyPubKey` | 32 bytes | x-only public key (= Taproot address) |
| `BTCQAddressHash` | 32 bytes | SHA256 of destination qbtc address |
| `ChainID` | 8 bytes | First 8 bytes of SHA256(chain_id) |

**Constraints**:
1. PublicKeyX matches XOnlyPubKey
2. Compute BIP-340 challenge: e = tagged_hash("BIP0340/challenge", R.x || P.x || m)
3. Verify Schnorr equation: s·G = R + e·P
4. PublicKeyY has even parity (BIP-340 requirement)

### 4.4 P2SH-P2WPKH Circuit

**File**: `x/qbtc/zk/circuit_p2sh_p2wpkh.go`

The `BTCP2SHP2WPKHCircuit` handles P2SH-wrapped SegWit addresses (addresses starting with "3"):

**Public Inputs**:
| Field | Size | Description |
|-------|------|-------------|
| `MessageHash` | 32 bytes | SHA256 of the claim message |
| `ScriptHash` | 20 bytes | Hash160 of the redeem script |
| `BTCQAddressHash` | 32 bytes | SHA256 of destination qbtc address |
| `ChainID` | 8 bytes | First 8 bytes of SHA256(chain_id) |

**Constraints**:
1. ECDSA signature verification
2. Compute pubkeyHash = Hash160(compressed_pubkey)
3. Build redeemScript = OP_0 || 0x14 || pubkeyHash
4. Hash160(redeemScript) == ScriptHash

### 4.5 P2PK Circuit (Legacy)

**File**: `x/qbtc/zk/circuit_p2pk.go`

The `BTCP2PKCircuit` handles legacy P2PK outputs where the raw public key is in the script:

**Public Inputs**:
| Field | Size | Description |
|-------|------|-------------|
| `MessageHash` | 32 bytes | SHA256 of the claim message |
| `CompressedPubKey` | 33 bytes | Raw compressed public key from script |
| `BTCQAddressHash` | 32 bytes | SHA256 of destination qbtc address |
| `ChainID` | 8 bytes | First 8 bytes of SHA256(chain_id) |

**Constraints**:
1. ECDSA signature verification
2. Compress public key (from private circuit input)
3. compressed_pubkey == CompressedPubKey

### 4.6 P2WSH Single-Key Circuit

**File**: `x/qbtc/zk/circuit_p2wsh_single_key.go`

The `BTCP2WSHSingleKeyCircuit` handles P2WSH addresses with single-key witness scripts:

**Public Inputs**:
| Field | Size | Description |
|-------|------|-------------|
| `MessageHash` | 32 bytes | SHA256 of the claim message |
| `WitnessProgram` | 32 bytes | SHA256 of the witness script |
| `BTCQAddressHash` | 32 bytes | SHA256 of destination qbtc address |
| `ChainID` | 8 bytes | First 8 bytes of SHA256(chain_id) |

**Constraints**:
1. ECDSA signature verification
2. Compress public key
3. Build witnessScript = 0x21 || compressed_pubkey || OP_CHECKSIG
4. SHA256(witnessScript) == WitnessProgram

### 4.7 Circuit Constraints Detail

Each circuit's `Define()` method enforces constraint groups:

#### Constraint Group 1: Signature Verification

For ECDSA circuits, gnark's standard `ecdsa.Verify` gadget is used.
For Schnorr, a custom implementation verifies: s·G = R + e·P

**What this proves**: The prover knows a valid signature for `MessageHash` under the claimed public key.

#### Constraint Group 2: Public Key to Address Binding

Each circuit type has specific binding logic:
- **P2PKH/P2WPKH**: Hash160(compressed_pubkey) == AddressHash
- **P2TR**: PublicKeyX == XOnlyPubKey (with even Y parity)
- **P2SH-P2WPKH**: Hash160(redeemScript) == ScriptHash
- **P2PK**: compressed_pubkey == CompressedPubKey
- **P2WSH**: SHA256(witnessScript) == WitnessProgram

**What this proves**: The public key corresponds to the claimed Bitcoin address/script.

#### Constraint Group 3: Message Binding (Verified by Verifier)

The verifier independently computes the expected message hash from the claim parameters. If the computed message doesn't match `MessageHash`, verification fails.

**What this proves**: The signature was created for the specific claim parameters (address, destination, chain).

### 4.3 Public Key Compression (In-Circuit)

**File**: `x/qbtc/zk/circuit_signature.go`, function `compressPubKeyFromPoint`

Bitcoin uses compressed public keys (33 bytes):
- Byte 0: `0x02` if Y is even, `0x03` if Y is odd
- Bytes 1-32: X coordinate (big-endian)

The circuit extracts bits from X and Y coordinates, determines Y parity from the LSB, constructs the prefix byte, and packs X bits into 32 big-endian bytes.

### 4.4 Hash160 Implementation (In-Circuit)

**File**: `x/qbtc/zk/hash.go`

#### SHA-256
Uses gnark's standard library implementation (`std/hash/sha2`).

#### RIPEMD-160
Custom implementation following the RIPEMD-160 specification:
- 5 × 32-bit state words (160 bits total)
- 80 rounds per block (two parallel lines)
- 5 different boolean functions per round
- Message padding with length encoding

**Key operations**: Round function selection, 32-bit modular addition, bit rotation, and bitwise XOR/AND/OR/NOT operations.

**Constraint cost**: RIPEMD-160 is the most expensive part of the circuit due to bitwise operations on 32-bit words.

### 4.5 Byte-to-Scalar Conversion

**File**: `x/qbtc/zk/circuit_signature.go`, function `bytesToScalar`

Converts 32 bytes (message hash) to a secp256k1 scalar field element:
- Input: 32 bytes in big-endian
- Output: 4 limbs × 64 bits (gnark's emulated field representation)

The conversion handles big-endian to little-endian limb ordering and proper bit packing.

---

## 5. Message Format and Binding

### 5.1 Claim Message Structure

**File**: `x/qbtc/zk/message.go`

```
MessageHash = SHA256(AddressHash || BTCQAddressHash || ChainID || "qbtc-claim-v1")
```

| Component | Size | Description |
|-----------|------|-------------|
| `AddressHash` | 20 bytes | Hash160 of Bitcoin public key |
| `BTCQAddressHash` | 32 bytes | SHA256(destination_qbtc_address) |
| `ChainID` | 8 bytes | First 8 bytes of SHA256(chain_id_string) |
| Version | 13 bytes | Literal string "qbtc-claim-v1" |

**Total preimage**: 73 bytes

### 5.2 Binding Properties

| Binding | Prevents |
|---------|----------|
| `AddressHash` | Claiming someone else's Bitcoin |
| `BTCQAddressHash` | Front-running (proof only works for intended recipient) |
| `ChainID` | Cross-chain replay attacks |
| Version string | Cross-version replay attacks |

---

## 6. Trusted Setup

### 6.1 Structured Reference String (SRS)

PLONK requires a universal SRS derived from a Powers of Tau ceremony.

**Production**: Uses the Hermez/Polygon Powers of Tau ceremony:
- URL: `https://storage.googleapis.com/zkevm/ptau/powersOfTau28_hez_final_21.ptau`
- Default power: 21 (2²¹ = ~2M constraints)
- Participants: 54+ independent contributors  
- Security: 1-of-N honest participant assumption

**Blake2b hash** (from [snarkjs docs](https://github.com/iden3/snarkjs#7-prepare-phase-2)):
- Power 21: `9aef0573cef4ded9c4a75f148709056bf989f80dad96876aadeb6f1c6d062391f07a394a9e756d16f7eb233198d5b69407cca44594c763ab4a5b67ae73254678`

Downloaded PTAU files are verified against this hash before use.

### 6.2 Setup Modes

**File**: `x/qbtc/zk/setup.go`

| Mode | Description | Use Case |
|------|-------------|----------|
| `SetupModeTest` | Unsafe test SRS | Development/testing only |
| `SetupModeFile` | Load from file | Custom SRS |
| `SetupModeDownload` | Download Hermez PTAU | Production |

### 6.3 PTAU Conversion

The Hermez PTAU format is converted to gnark's SRS format:
1. Parse PTAU sections (G1 points, G2 points)
2. Validate all points are on the curve
3. Construct gnark SRS structure with proving and verifying keys

**Security Note**: The toxic waste τ is never reconstructed. Only the points [τⁱ]G are used.

### 6.4 Verifying Key Distribution

The verifying key (VK) is:
1. Generated during setup
2. Serialized to hex
3. Embedded in chain genesis
4. Loaded once at node startup
5. Immutable thereafter

---

## 7. Proof Generation

### 7.1 Prover Interface

**File**: `x/qbtc/zk/setup.go`

The `Prover` struct holds the constraint system and proving key. The `ProofParams` struct contains all inputs needed for proof generation:
- Signature components (r, s as big integers)
- Public key coordinates (x, y as big integers)
- Message hash (32 bytes)
- Address hash (20 bytes)
- BTCQ address hash (32 bytes)
- Chain ID (8 bytes)

### 7.2 Proof Generation Flow

1. Create witness assignment from ProofParams
2. Convert big integers to gnark's emulated field limbs
3. Create full witness (private + public inputs)
4. Generate PLONK proof using constraint system and proving key
5. Serialize proof to bytes

### 7.3 Proof Serialization Format

Wire format: `[4-byte proof length (big-endian)][proof data][public inputs witness]`

**Validation constraints**:
- Minimum proof length: 100 bytes
- Maximum proof length: 1 MB

---

## 8. Proof Verification

### 8.1 Global Verifier

**File**: `x/qbtc/zk/verifier.go`

The verifier is a thread-safe singleton initialized once from genesis. After initialization, the `initialized` flag prevents any re-registration, protecting against VK replacement attacks.

### 8.2 Verification Flow

1. **Message binding check**: Compute expected message hash from verification parameters; reject if mismatch
2. **Proof deserialization**: Parse PLONK proof from bytes
3. **Public witness construction**: Create witness with only public inputs
4. **PLONK verification**: Call gnark's PLONK verifier with proof, VK, and witness

### 8.3 On-Chain Handler

**File**: `x/qbtc/keeper/handle_msg_claim_with_proof.go`

The handler:
1. Finds the first valid UTXO to determine the proven Bitcoin address
2. Computes verification parameters (message hash, address hash, etc.)
3. Calls the global verifier
4. On success, claims all matching UTXOs by minting tokens and zeroing EntitledAmount

---

## 9. Security Analysis

### 9.1 Threat Model

| Actor | Capabilities | Goal |
|-------|--------------|------|
| **Malicious User** | Can generate arbitrary proofs | Claim UTXOs they don't own |
| **Malicious Node** | Controls a validator | Forge proofs or modify VK |
| **Front-runner** | Observes mempool | Intercept proof and claim for themselves |
| **Replayer** | Has valid proof from another chain | Reuse proof on this chain |

### 9.2 Security Properties

#### 9.2.1 Soundness

**Claim**: A computationally bounded adversary cannot generate a valid proof for an address they don't control.

**Argument**:
1. PLONK is computationally sound under the algebraic group model
2. Circuit enforces: valid ECDSA signature ∧ pubkey hashes to address
3. Breaking soundness requires either:
   - Breaking ECDSA (forge signature)
   - Breaking PLONK (forge proof)
   - Finding Hash160 collision (find different pubkey with same hash)

All three are computationally infeasible.

#### 9.2.2 Zero-Knowledge

**Claim**: The proof reveals nothing about the signature or public key.

**Argument**:
1. SignatureR, SignatureS, PublicKeyX, PublicKeyY are marked as secret inputs
2. PLONK is zero-knowledge: proofs are simulatable without witness
3. Only public inputs (hashes) are revealed

#### 9.2.3 Front-Running Resistance

**Claim**: An attacker who observes a proof cannot redirect the claim.

**Argument**:
1. Proof commits to `BTCQAddressHash = SHA256(claimer_address)`
2. Verifier recomputes expected message including BTCQAddressHash
3. If attacker submits with different claimer, message hash won't match
4. Proof verification fails

#### 9.2.4 Replay Resistance

**Claim**: A proof cannot be reused on a different chain or after protocol upgrade.

**Argument**:
1. ChainID is bound into the signed message
2. ClaimMessageVersion ("qbtc-claim-v1") is bound into the message
3. Cross-chain or cross-version replay changes expected message hash
4. Proof verification fails

#### 9.2.5 Double-Spend Prevention

**Claim**: The same UTXO cannot be claimed twice.

**Argument**:
1. After successful claim, UTXO.EntitledAmount is set to 0
2. Handler skips UTXOs with EntitledAmount == 0
3. Subsequent claims for same UTXO will find no claimable amount

### 9.3 Attack Vectors and Mitigations

| Attack | Mitigation | Code Reference |
|--------|------------|----------------|
| VK replacement | Verifier immutable after init | `verifier.go:128` |
| Proof forgery | PLONK soundness | gnark library |
| Signature forgery | ECDSA security | secp256k1 |
| Address collision | Hash160 collision resistance | 160-bit security |
| Front-running | BTCQAddressHash binding | `message.go:23` |
| Cross-chain replay | ChainID binding | `message.go:28` |
| Version replay | Version string binding | `message.go:29` |
| Double-spend | EntitledAmount zeroing | `handle_msg_claim_with_proof.go:157` |
| DoS via large proof | Max proof size 1MB | `setup.go:30` |
| DoS via many UTXOs | Max 50 UTXOs per batch | protobuf validation |

### 9.4 Trust Assumptions

1. **Trusted Setup**: At least one participant in Hermez ceremony was honest
2. **Cryptographic Hardness**: ECDSA, SHA-256, RIPEMD-160, BN254 pairings are secure
3. **Implementation Correctness**: gnark library is correctly implemented
4. **Genesis Integrity**: VK in genesis is correct and matches proving key

---

## 10. Implementation Details

### 10.1 Field Emulation

secp256k1 operations are emulated over BN254's scalar field using gnark's `std/math/emulated` package:

- **Fp** (base field): 256-bit prime, represented as 4 × 64-bit limbs
- **Fr** (scalar field): 256-bit prime, represented as 4 × 64-bit limbs
- Operations use multi-precision arithmetic with range checks

### 10.2 Constraint Count

Approximate constraint breakdown:

| Component | Constraints |
|-----------|-------------|
| ECDSA verification | ~800,000 |
| Public key compression | ~5,000 |
| SHA-256 (in Hash160) | ~30,000 |
| RIPEMD-160 | ~50,000 |
| **Total** | **~900,000** |

### 10.3 Performance Characteristics

| Operation | Time | Memory |
|-----------|------|--------|
| Circuit compilation | ~30s | ~2 GB |
| Proof generation | ~60s | ~8 GB |
| Proof verification | ~3ms | ~50 MB |
| Proof size | - | ~1 KB |

---

## 11. File Reference

### 11.1 Core Implementation

| File | Purpose |
|------|---------|
| `x/qbtc/zk/circuit_signature.go` | ECDSA circuit (P2PKH/P2WPKH) |
| `x/qbtc/zk/circuit_schnorr.go` | Schnorr circuit (P2TR/Taproot) |
| `x/qbtc/zk/circuit_p2sh_p2wpkh.go` | P2SH-P2WPKH circuit |
| `x/qbtc/zk/circuit_p2pk.go` | P2PK circuit (legacy) |
| `x/qbtc/zk/circuit_p2wsh_single_key.go` | P2WSH single-key circuit |
| `x/qbtc/zk/hash.go` | SHA-256 and RIPEMD-160 in-circuit |
| `x/qbtc/zk/tagged_hash.go` | BIP-340 tagged hash implementation |
| `x/qbtc/zk/message.go` | Claim message construction |
| `x/qbtc/zk/setup.go` | PLONK setup and provers |
| `x/qbtc/zk/verifier.go` | Global verifier and verification |
| `x/qbtc/zk/multi_verifier.go` | Multi-circuit routing verifier |
| `x/qbtc/zk/btc.go` | Bitcoin address utilities |

### 11.2 Integration

| File | Purpose |
|------|---------|
| `x/qbtc/keeper/genesis.go` | VK loading from genesis |
| `x/qbtc/keeper/handle_msg_claim_with_proof.go` | On-chain claim handler |
| `cmd/zkprover/main.go` | CLI proof generation tool |
| `cmd/tss-emulator/main.go` | TSS signer emulator for testing |

### 11.3 Tests

| File | Coverage |
|------|----------|
| `x/qbtc/zk/circuit_signature_test.go` | ECDSA circuit end-to-end tests |
| `x/qbtc/zk/integration_test.go` | Full claim flow simulation |
| `x/qbtc/zk/multi_script_test.go` | Multi-script type coverage tests |
| `x/qbtc/zk/security_audit_test.go` | Security property verification |
| `x/qbtc/keeper/handle_msg_claim_with_proof_test.go` | Handler integration tests |

### 11.4 Protocol Buffers

| File | Purpose |
|------|---------|
| `proto/qbtc/qbtc/v1/msg_claim_with_proof.proto` | Message definitions |

---

## Appendix A: TSS/MPC Integration

### A.1 Required TSS API

**Endpoint**: `POST /sign`

**Request**: JSON object with `message_hash` field (64 hex characters)

**Response**: JSON object with:
- `signature.r`: 32-byte scalar (big-endian hex)
- `signature.s`: 32-byte scalar (big-endian hex)
- `signature.v`: Recovery ID (0 or 1)
- `public_key`: 33-byte compressed SEC1 format (66 hex characters)

### A.2 TSS Emulator

For testing, use the provided emulator:
```bash
tss-emulator --port :8080 --private-key <32-byte-hex>
```

---

## 12. Supported Bitcoin Script Types

### 12.1 Full Support

#### P2PKH (Pay-to-Public-Key-Hash)
- **Address format**: `1...` (Base58Check, mainnet)
- **Script**: `OP_DUP OP_HASH160 <pubkeyHash> OP_EQUALVERIFY OP_CHECKSIG`
- **Circuit**: `BTCSignatureCircuit`
- **Binding**: Hash160(compressed_pubkey) == AddressHash

#### P2WPKH (Pay-to-Witness-Public-Key-Hash)
- **Address format**: `bc1q...` (Bech32, 42 characters)
- **Script**: `OP_0 <20-byte-pubkeyHash>`
- **Circuit**: `BTCSignatureCircuit`
- **Binding**: Hash160(compressed_pubkey) == AddressHash

#### P2TR (Pay-to-Taproot) - Key Path Only
- **Address format**: `bc1p...` (Bech32m, 62 characters)
- **Script**: `OP_1 <32-byte-x-only-pubkey>`
- **Circuit**: `BTCSchnorrCircuit`
- **Signature**: BIP-340 Schnorr
- **Binding**: PublicKeyX == XOnlyPubKey (even Y parity)

#### P2SH-P2WPKH (Wrapped SegWit)
- **Address format**: `3...` (Base58Check)
- **Script**: `OP_HASH160 <scriptHash> OP_EQUAL`
- **RedeemScript**: `OP_0 <20-byte-pubkeyHash>`
- **Circuit**: `BTCP2SHP2WPKHCircuit`
- **Binding**: Hash160(redeemScript) == ScriptHash

#### P2PK (Pay-to-Public-Key)
- **Address format**: None (raw script)
- **Script**: `<pubkey> OP_CHECKSIG`
- **Circuit**: `BTCP2PKCircuit`
- **Binding**: compressed_pubkey == CompressedPubKey

#### P2WSH (Pay-to-Witness-Script-Hash) - Single Key
- **Address format**: `bc1q...` (Bech32, 62 characters)
- **Script**: `OP_0 <32-byte-witnessProgram>`
- **WitnessScript**: `<pubkey> OP_CHECKSIG`
- **Circuit**: `BTCP2WSHSingleKeyCircuit`
- **Binding**: SHA256(witnessScript) == WitnessProgram

### 12.2 Not Supported

#### P2WSH Multisig
- **Reason**: Requires embedding Bitcoin script interpreter in ZK circuit
- **Complexity**: Variable number of signatures and threshold logic
- **Alternative**: Individual key holders can claim their share separately

#### P2TR Script Path
- **Reason**: Requires MAST (Merkleized Abstract Syntax Trees) verification
- **Complexity**: Arbitrary script execution in ZK circuit
- **Alternative**: Use key-path spending if possible

#### Generic P2SH
- **Reason**: Arbitrary redeem scripts impossible to verify generically
- **Supported subset**: Only P2SH-P2WPKH (most common use case)

### 12.3 Address Type Detection

The system automatically detects address types:

```go
func DetectAddressType(address string) AddressType {
    // P2PKH: starts with "1"
    // P2SH:  starts with "3"
    // P2WPKH: starts with "bc1q", 42 chars
    // P2WSH: starts with "bc1q", 62 chars
    // P2TR: starts with "bc1p"
}
```

### 12.4 Multi-Verifier Routing

The `MultiVerifier` automatically routes proofs to the correct circuit verifier:

```go
type CircuitType int
const (
    CircuitTypeECDSA        CircuitType = iota  // P2PKH, P2WPKH
    CircuitTypeSchnorr                           // P2TR
    CircuitTypeP2SHP2WPKH                        // P2SH-P2WPKH
    CircuitTypeP2PK                              // P2PK
    CircuitTypeP2WSHSingleKey                    // P2WSH single-key
)
```

---

## 13. Security Audit Results

### 13.1 Properties Verified

| Property | Status | Test |
|----------|--------|------|
| **Soundness** | ✅ Verified | Invalid proofs rejected |
| **Zero-Knowledge** | ✅ Verified | Signatures/keys remain private |
| **Address Binding** | ✅ Verified | Proof bound to Bitcoin address |
| **Destination Binding** | ✅ Verified | Front-running protection |
| **Chain Binding** | ✅ Verified | Cross-chain replay protection |
| **Verifier Immutability** | ✅ Verified | VK replacement attacks blocked |

### 13.2 Attack Scenarios Tested

| Attack | Result |
|--------|--------|
| Claim someone else's address | ❌ BLOCKED - constraint fails |
| Invalid signature | ❌ BLOCKED - verification fails |
| Front-running proof interception | ❌ BLOCKED - proof bound to destination |
| Cross-chain replay | ❌ BLOCKED - chain ID mismatch |
| VK replacement | ❌ BLOCKED - verifier immutable |

### 13.3 Test Coverage

```
x/qbtc/zk/security_audit_test.go     - Security property tests
x/qbtc/zk/multi_script_test.go       - Script type coverage tests
x/qbtc/zk/circuit_signature_test.go  - ECDSA circuit tests
x/qbtc/zk/integration_test.go        - Full flow tests
```