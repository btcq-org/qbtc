# ZK Proof System Technical Specification

**Version**: 1.0  
**Last Updated**: November 2025 
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

---

## 1. Executive Summary

### 1.1 Purpose

The qbtc ZK proof system enables users to claim Bitcoin UTXOs on the qbtc chain by proving ownership of a Bitcoin address **without revealing**:
- The private key
- The public key  
- The ECDSA signature

This is achieved through a PLONK zero-knowledge proof that demonstrates knowledge of a valid ECDSA signature for a specific message, where the public key hashes to the claimed Bitcoin address.

### 1.2 Design Goals

| Goal | Implementation |
|------|----------------|
| **TSS/MPC Compatibility** | Only requires a signature; no private key access needed |
| **Privacy** | Signature and public key are private circuit inputs |
| **Front-running Protection** | Proof bound to destination address |
| **Replay Protection** | Chain ID and version string in signed message |
| **Double-spend Prevention** | UTXO marked as claimed after successful verification |

### 1.3 Key Parameters

| Parameter | Value |
|-----------|-------|
| Proof System | PLONK with KZG commitments |
| Pairing Curve | BN254 (alt_bn128) |
| Signature Curve | secp256k1 |
| Hash Functions | SHA-256, RIPEMD-160 |
| Trusted Setup | Hermez/Polygon Powers of Tau (2²⁰) |
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

### 4.1 Circuit Structure

**File**: `x/qbtc/zk/circuit_signature.go`

The `BTCSignatureCircuit` contains:

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

### 4.2 Circuit Constraints

The `Define()` method enforces three constraint groups:

#### Constraint Group 1: ECDSA Signature Verification

The circuit constructs the public key and signature from private inputs, converts the message hash to a scalar, and calls gnark's ECDSA verification gadget.

**What this proves**: The prover knows a valid ECDSA signature `(r, s)` for `MessageHash` under the public key `(PublicKeyX, PublicKeyY)`.

#### Constraint Group 2: Public Key to Address Binding

The circuit compresses the public key to 33 bytes (SEC1 format), computes Hash160 = RIPEMD160(SHA256(compressed_pubkey)), and asserts each byte equals the corresponding byte in `AddressHash`.

**What this proves**: The public key, when compressed and hashed, equals the claimed `AddressHash`.

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
- URL: `https://hermez.s3-eu-west-1.amazonaws.com/powersOfTau28_hez_final_20.ptau`
- Power: 2²⁰ (~1M constraints supported)
- Participants: 54+ independent contributors
- Security: 1-of-N honest participant assumption

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
| `x/qbtc/zk/circuit_signature.go` | Circuit definition and constraints |
| `x/qbtc/zk/hash.go` | SHA-256 and RIPEMD-160 in-circuit |
| `x/qbtc/zk/message.go` | Claim message construction |
| `x/qbtc/zk/setup.go` | PLONK setup and prover |
| `x/qbtc/zk/verifier.go` | Global verifier and verification |
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
| `x/qbtc/zk/circuit_signature_test.go` | Circuit end-to-end tests |
| `x/qbtc/zk/integration_test.go` | Full claim flow simulation |
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