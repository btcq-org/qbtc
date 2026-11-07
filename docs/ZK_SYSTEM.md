# ZK Proof System Technical Specification

**Version**: 3.0  
**Last Updated**: November 2026
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
- The ECDSA signature

This is achieved through PLONK zero-knowledge proofs that demonstrate knowledge of a valid signature for a specific message, where the public key corresponds to the claimed Bitcoin address.

The signed message is an ordinary BIP-137 "Bitcoin Signed Message", so any wallet with a "Sign message" feature (Electrum, Sparrow, Ledger, Trezor, Bitcoin Core for legacy addresses) can produce the signature. TSS/MPC signers work too: they sign the same 32-byte digest.

### 1.2 Supported Bitcoin Address Types

| Address Type           | Prefix            | Circuit | Status           |
| ---------------------- | ----------------- | ------- | ---------------- |
| **P2PKH**              | `1...`            | ECDSA   | ✅ Supported     |
| **P2WPKH**             | `bc1q...` (short) | ECDSA   | ✅ Supported     |
| All other script types | -                 | -       | ❌ Not Supported |

### 1.3 Design Goals

| Goal                         | Implementation                                          |
| ---------------------------- | ------------------------------------------------------- |
| **Wallet Compatibility**     | Signature is a BIP-137 signed message; works with wallets and TSS/MPC |
| **Privacy**                  | Signature and public key are private circuit inputs     |
| **Front-running Protection** | Proof bound to destination address                      |
| **Replay Protection**        | Chain ID, address and version string in signed message  |
| **Double-spend Prevention**  | UTXO marked as claimed after successful verification    |

### 1.4 Key Parameters

| Parameter         | Value                                          |
| ----------------- | ---------------------------------------------- |
| Proof System      | PLONK with KZG commitments                     |
| Pairing Curve     | BN254 (alt_bn128)                              |
| Signature Curve   | secp256k1 (ECDSA)                              |
| Hash Functions    | SHA-256, RIPEMD-160                            |
| Trusted Setup     | Hermez/Polygon Powers of Tau (2²¹)             |
| Proof Size        | 584 bytes                                      |
| Verification Time | ~2-5 ms                                        |

---

## 2. System Architecture

### 2.1 High-Level Flow

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              USER DOMAIN                                     │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  ┌─────────────┐    1. Sign Message    ┌──────────────┐                    │
│  │ Bitcoin     │ ──────────────────────▶│  zkprover   │                    │
│  │ wallet or   │◀────────────────────── │  CLI Tool   │                    │
│  │ TSS signer  │   (BIP-137 signature)  │             │                    │
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

1. **Message Construction**: `zkprover message` prints the claim text `qbtc-claim-v1|<chain-id>|<bitcoin address>|<destination qbtc address>` (see Section 5)

2. **Signature**: The user signs that text in their Bitcoin wallet ("Sign message", BIP-137), or a TSS/MPC signer signs its 32-byte BIP-137 digest with ECDSA on secp256k1

3. **Proof Generation**: zkprover recovers the public key from the signature and creates a PLONK proof with private inputs (signature, public key) and only two public inputs: `MessageHash` (the BIP-137 digest) and `PubKeyHashSHA256` (SHA256 of the SEC-compressed pubkey). The chain ID, Bitcoin address and destination are *not* circuit public inputs — they bind to the proof via `MessageHash`, which the verifier re-derives.

4. **On-chain Verification**: Handler rebuilds the claim text from the chain ID, the UTXO's stored Bitcoin address and the destination (receiver or claimer), computes its BIP-137 digest as `MessageHash`, natively checks `RIPEMD160(PubKeyHashSHA256) == Hash160(address)`, and verifies the PLONK proof against the two public inputs.

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

- **Native (verifier-side)**: `golang.org/x/crypto/ripemd160`, applied to the circuit's `PubKeyHashSHA256` public input
- **Used for**: Closing the Hash160 binding — verifier asserts `RIPEMD160(PubKeyHashSHA256) == AddressHash`
- **Not in-circuit**: the in-circuit RIPEMD-160 gadget was removed; running it natively costs microseconds and cut ~320K constraints from the SNARK

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

The ZK system uses a single circuit, `BTCPubKeyOwnershipCircuit`, covering P2PKH and P2WPKH addresses via ECDSA + Hash160.

### 4.1 Circuit Overview

| Circuit                      | File                   | Script Types  | Signature |
| ---------------------------- | ---------------------- | ------------- | --------- |
| `BTCPubKeyOwnershipCircuit` | `circuit.go`           | P2PKH, P2WPKH | ECDSA     |

### 4.2 ECDSA Circuit (P2PKH/P2WPKH)

**File**: `x/qbtc/zk/circuit.go`

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
| `MessageHash` | 32 bytes | BIP-137 digest (double SHA-256) of the claim text, see Section 5.2 |
| `PubKeyHashSHA256` | 32 bytes | SHA256 of the 33-byte SEC-compressed pubkey |

The chain ID, the Bitcoin address and the destination qbtc address are *not* circuit public inputs. The verifier takes them from chain state and the message, and binds them natively:

- `MessageHash == BIP137Digest("qbtc-claim-v1|chainID|bitcoinAddress|destination")` ties the chain, the address and the destination to the proof.
- `RIPEMD160(PubKeyHashSHA256) == Hash160(bitcoinAddress)` closes the Hash160 binding to the Bitcoin address.

Keeping RIPEMD160 and the message derivation out of the circuit roughly halves prover time, and lets the message format change without touching the circuit or the verifying key.

### 4.3 Circuit Constraints Detail

The `Define()` method enforces two constraint groups. A third binding — message derivation — is completed natively by the verifier.

#### Constraint Group 1: Signature Verification

gnark's standard `ecdsa.Verify` gadget verifies the ECDSA signature against the public key and message hash.

**What this proves**: The prover knows a valid signature for `MessageHash` under the claimed public key.

#### Constraint Group 2: Public Key Commitment

The public key is a finite point on secp256k1, and `SHA256(SEC-compressed pubkey) == PubKeyHashSHA256`.

`ecdsa.Verify` does not check that the key is on the curve, so the circuit asserts it (`compressCheckedPubKey`). gnark's `AssertIsOnCurve` accepts `(0, 0)` as the point at infinity, so that point is rejected separately.

**What this proves**: The public key used to verify the signature matches the claimed SHA256 commitment. The verifier then natively applies RIPEMD160 to recover the Bitcoin `AddressHash`.

#### Constraint Group 3: Message Binding (Native in Verifier)

The verifier independently computes the BIP-137 digest of the claim text and uses it as the `MessageHash` public input. A proof made for any other text fails PLONK verification.

**What this proves**: The signature was created for the specific claim parameters (chain, address, destination).

### 4.4 Public Key Compression (In-Circuit)

**File**: `x/qbtc/zk/hash.go`, functions `compressCheckedPubKey` and `compressPubKeyFromPoint`

Bitcoin uses compressed public keys (33 bytes):

- Byte 0: `0x02` if Y is even, `0x03` if Y is odd
- Bytes 1-32: X coordinate (big-endian)

The circuit extracts the canonical bits (below the field modulus) of the X and Y coordinates with `ToBitsCanonical`, determines Y parity from the LSB, constructs the prefix byte, and packs X bits into 32 big-endian bytes. With plain `ToBits`, a witness could give X as `x + p`, which is the same point but would hash to a different byte string.

### 4.5 Pubkey Hashing (Split Between Circuit and Verifier)

**File**: `x/qbtc/zk/hash.go` (in-circuit); `x/qbtc/zk/verifier.go` (native).

- **SHA-256** runs in-circuit via gnark's `std/hash/sha2` and commits the compressed pubkey to the public input `PubKeyHashSHA256`.
- **RIPEMD-160** runs natively in the verifier via `golang.org/x/crypto/ripemd160`, closing the binding to the 20-byte `AddressHash`.

This split preserves full Hash160 soundness (RIPEMD160 is collision-resistant) while cutting out ~320K constraints that a prior in-circuit RIPEMD160 gadget added. The dominant in-circuit cost is now ECDSA verification (~800K constraints); SHA-256 over the 33-byte compressed pubkey contributes ~170K.

### 4.6 Byte-to-Scalar Conversion

**File**: `x/qbtc/zk/hash.go`, function `bytesToScalar`

Converts 32 bytes (message hash) to a secp256k1 scalar field element:

- Input: 32 bytes in big-endian
- Output: 4 limbs × 64 bits (gnark's emulated field representation)

The conversion handles big-endian to little-endian limb ordering and proper bit packing.

---

## 5. Message Format and Binding

### 5.1 Claim Message Text

**File**: `x/qbtc/zk/message.go`

The user signs a single line of ASCII text:

```
qbtc-claim-v1|<chain-id>|<bitcoin address>|<destination qbtc address>
```

| Field           | Example                                      | Source                                          |
| --------------- | -------------------------------------------- | ----------------------------------------------- |
| Version         | `qbtc-claim-v1`                              | `ClaimMessageVersion`                           |
| Chain ID        | `qbtc-1`                                     | `sdk.Context.ChainID()`                         |
| Bitcoin address | `bc1q4wr4k0uwzryx9jyss3tsd60gaulpxaggzm3mnc` | `UTXO.ScriptPubKey.Address`, byte for byte      |
| Destination     | `qbtc1...`                                   | `MsgClaimWithProof.receiver`, else `.claimer`   |

Neither address alphabet (base58, bech32) contains `|`, so the text parses unambiguously even if the chain ID contains one. The text is one line with no trailing newline, which survives every wallet's message dialog unchanged.

### 5.2 BIP-137 Digest

The ECDSA message scalar is the standard "Bitcoin Signed Message" digest:

```
MessageHash = SHA256(SHA256(varstr("Bitcoin Signed Message:\n") || varstr(text)))
```

where `varstr` is a Bitcoin compact-size length prefix followed by the bytes. This is exactly what `bitcoin-cli signmessage`, Electrum, Sparrow, Ledger and Trezor sign. The magic prefix guarantees the digest can never be a valid transaction hash. A TSS/MPC signer signs this 32-byte digest directly.

### 5.3 Signature Encoding

Wallets return a base64 string of 65 bytes: `header || r (32) || s (32)`. The header encodes the recovery id and, informally, the address type:

| Header | Meaning                          | Accepted |
| ------ | -------------------------------- | -------- |
| 27..30 | P2PKH, uncompressed public key   | No       |
| 31..34 | P2PKH, compressed public key     | Yes      |
| 35..38 | P2SH-P2WPKH                      | Yes*     |
| 39..42 | P2WPKH                           | Yes      |

Wallets disagree on which range to use for segwit addresses, so `zk.ParseBIP137Signature` accepts every header from 31 to 42 and uses only its recovery id (`(header-27) & 3`) to recover the public key with `RecoverCompact`. The recovered key must then own the claimed address (`zk.CheckPubKeyOwnsAddress`); a P2SH-P2WPKH signature recovers fine but fails that check because the address type is unsupported.

Headers 27 to 30 are rejected: the circuit commits to the 33-byte compressed public key, so addresses derived from an uncompressed key cannot be claimed.

### 5.4 Binding Properties

| Binding         | Prevents                                                |
| --------------- | ------------------------------------------------------- |
| Bitcoin address | Claiming someone else's Bitcoin (together with Hash160) |
| Destination     | Front-running (proof only works for intended recipient) |
| Chain ID        | Cross-chain replay attacks                              |
| Version string  | Cross-version replay attacks                            |

---

## 6. Trusted Setup

### 6.1 Structured Reference String (SRS)

PLONK requires a universal SRS derived from a Powers of Tau ceremony.

**Production**: Uses the Hermez/Polygon Powers of Tau ceremony:

- URL: `https://circom.info/powersOfTau28_hez_final_21.ptau` (the former `storage.googleapis.com/zkevm/ptau` location returns HTTP 403)
- Default power: 21 (2²¹ = ~2M constraints)
- Participants: 54+ independent contributors
- Security: 1-of-N honest participant assumption

**Blake2b hashes** (from [snarkjs docs](https://github.com/iden3/snarkjs#7-prepare-phase-2)):

- Power 21: `9aef0573cef4ded9c4a75f148709056bf989f80dad96876aadeb6f1c6d062391f07a394a9e756d16f7eb233198d5b69407cca44594c763ab4a5b67ae73254678`
- Power 22: `0d64f63dba1a6f11139df765cb690da69d9b2f469a1ddd0de5e4aa628abb28f787f04c6a5fb84a235ec5ea7f41d0548746653ecab0559add658a83502d1cb21b`
- Power 23: `3063a0bd81d68711197c8820a92466d51aeac93e915f5136d74f63c394ee6d88c5e8016231ea6580bec02e25d491f319d92e77f5c7f46a9caa8f3b53c0ea544f`

PTAU files are verified against these hashes before use, including a file already in the cache. A power without a pinned hash is refused. The gnark SRS is always derived from the verified PTAU file; converted SRS files are not cached.

**Verifying key check**: genesis validation (`qbtcd genesis validate`) rejects a verifying key whose KZG `[τ]G2` point is not the Hermez one, or whose number of public inputs is not 64. A key from the unsafe test SRS fails this check. See `zk.ValidateClaimVerifyingKey`.

### 6.2 Setup Modes

**File**: `x/qbtc/zk/setup.go`

| Mode                | Description          | Use Case                 |
| ------------------- | -------------------- | ------------------------ |
| `SetupModeTest`     | Unsafe test SRS      | Development/testing only |
| `SetupModeFile`     | Load from file       | Custom SRS               |
| `SetupModeDownload` | Download Hermez PTAU | Production               |

### 6.3 PTAU Conversion

The Hermez PTAU format is converted to gnark's SRS format:

1. Parse PTAU sections (G1 points, G2 points)
2. Validate all points are on the curve
3. Construct gnark SRS structure with proving and verifying keys
4. Compute the KZG verifying key's precomputed pairing lines from its G2 points (`srsFromPTAU`)

Step 4 matters: `gnark-ptau`'s `ToSRS` leaves the pairing lines at zero, and the KZG pairing check uses the lines, not the G2 points. With zero lines the pairing check accepts any input, which removes PLONK's soundness. Verifying keys built before this fix (including the first qbtc chain's key) have zero lines. As a second safeguard, `NewVerifier` recomputes the lines from the key's G2 points, and genesis validation rejects a key whose lines do not match.

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
- `MessageHash` (32 bytes, the BIP-137 digest)

`zk.ParseBIP137Signature` produces (r, s, pubkey) from a wallet's base64 signature and `zk.ProofParamsFromSignature` packs them. The chain ID, address and destination are not prover inputs — they bind to the proof via `MessageHash`.

### 7.2 Proof Generation Flow

1. Create witness assignment from ProofParams
2. Convert big integers to gnark's emulated field limbs
3. Create full witness (private + public inputs)
4. Generate PLONK proof using constraint system and proving key
5. Serialize proof to bytes

### 7.3 Proof Serialization Format

Wire format: `[4-byte proof length (big-endian)][proof data][public inputs witness]`

**Validation constraints**:

- The proof must have the exact compressed PLONK BN254 layout for the verifying key, checked by `CheckProofLayout` in `x/qbtc/zk/proof_layout.go`. For the claim circuit, which has one BSB22 commitment, that is 584 bytes.
- Both length prefixes must match the key: `BatchedProof.ClaimedValues` holds `6 + len(vk.Qcp)` scalars and `Bsb22Commitments` holds `len(vk.Qcp)` points.
- Every point must be compressed.

gnark-crypto allocates a point slice from its untrusted length prefix before reading any point, so a proof must pass this check before `plonk.Proof.ReadFrom` sees it. `ValidateBasic` runs it with the claim circuit's commitment count, and `VerifyProof` runs it again with the count taken from the stored verifying key.

---

## 8. Proof Verification

### 8.1 Global Verifier

**File**: `x/qbtc/zk/verifier.go`

The verifier is a thread-safe singleton initialized once from genesis. After initialization, the `initialized` flag prevents any re-registration, protecting against VK replacement attacks.

### 8.2 Verification Flow

1. **Address binding check**: Decode the Bitcoin address to its Hash160; reject unless `RIPEMD160(PubKeyHashSHA256)` equals it
2. **Message derivation**: Compute the BIP-137 digest of the claim text from `(ChainID, BitcoinAddress, QBTCAddress)`
3. **Proof deserialization**: Check the proof layout against the verifying key, then parse the PLONK proof from bytes
4. **Public witness construction**: Create witness with the derived `MessageHash` and the supplied `PubKeyHashSHA256`
5. **PLONK verification**: Call gnark's PLONK verifier with proof, VK, and witness

### 8.3 On-Chain Handler

**File**: `x/qbtc/keeper/handle_msg_claim_with_proof.go`

The handler:

1. Finds the first valid UTXO to determine the proven Bitcoin address string
2. Resolves the destination (receiver when set, otherwise claimer)
3. Calls the global verifier with the chain ID, the address, the destination and the supplied `pub_key_hash_sha256`
4. On success, claims the listed UTXOs whose stored address equals that string by minting tokens and zeroing EntitledAmount. UTXOs of the same key at its other address type are skipped, because the signature does not name them

---

## 9. Security Analysis

### 9.1 Threat Model

| Actor              | Capabilities                       | Goal                                     |
| ------------------ | ---------------------------------- | ---------------------------------------- |
| **Malicious User** | Can generate arbitrary proofs      | Claim UTXOs they don't own               |
| **Malicious Node** | Controls a validator               | Forge proofs or modify VK                |
| **Front-runner**   | Observes mempool                   | Intercept proof and claim for themselves |
| **Replayer**       | Has valid proof from another chain | Reuse proof on this chain                |

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

1. Proof commits to `MessageHash`, which the verifier re-derives from the claim text naming the destination address
2. If an attacker submits with a different claimer or receiver, the re-derived `MessageHash` won't match the one committed in the proof
3. Proof verification fails

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

| Attack              | Mitigation                    | Code Reference                       |
| ------------------- | ----------------------------- | ------------------------------------ |
| VK replacement      | Verifier immutable after init | `verifier.go:128`                    |
| Proof forgery       | PLONK soundness               | gnark library                        |
| Signature forgery   | ECDSA security                | secp256k1                            |
| Address collision   | Hash160 collision resistance  | 160-bit security                     |
| Front-running       | Destination in signed text    | `message.go`                         |
| Cross-chain replay  | Chain ID in signed text       | `message.go`                         |
| Version replay      | Version string in signed text | `message.go`                         |
| Double-spend        | EntitledAmount zeroing        | `handle_msg_claim_with_proof.go:157` |
| DoS via large proof | Exact proof layout check      | `proof_layout.go`                    |
| DoS via many UTXOs  | Max 50 UTXOs per batch        | protobuf validation                  |

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

Constraint breakdown with gnark v0.16.4. Components were compiled on their own, so they share range-check tables and do not add up exactly to the total:

| Component                          | Constraints   |
| ---------------------------------- | ------------- |
| ECDSA verification                 | ~687,000      |
| Public key checks and compression  | ~7,000        |
| SHA-256 (in circuit)               | ~496,000      |
| RIPEMD-160                         | native (~µs)  |
| **Total**                          | **1,202,299** |

With gnark v0.14.0 the total was 979,212. The gnark v0.16 soundness fixes ([GHSA-3mvx-pp85-pm65](https://github.com/Consensys/gnark/security/advisories/GHSA-3mvx-pp85-pm65)) add range checks to `std/math/uints`, which roughly triples the cost of SHA-256. The circuit now needs a 2²¹ PLONK domain.

### 10.3 Performance Characteristics

Measured on an Intel i7-6700 @ 3.40GHz, 8 threads, PLONK/BN254, test SRS, with gnark v0.14.0 (before the 1.21M-constraint circuit; expect slower proving now):

| Operation           | Time    | Memory  |
| ------------------- | ------- | ------- |
| Circuit compilation | ~30s    | ~2 GB   |
| Proof generation    | ~18s    | ~3 GB   |
| Proof verification  | ~3 ms   | ~50 MB  |
| Proof size          | 584 B   | —       |

Prior to the RIPEMD160-out-of-circuit change: ~1.3M constraints, ~36s proof, ~5 GB. See PR history for the benchmark comparison.

---

## 11. File Reference

### 11.1 Core Implementation

| File                             | Purpose                                        |
| -------------------------------- | ---------------------------------------------- |
| `x/qbtc/zk/circuit.go`           | ECDSA ownership circuit (P2PKH/P2WPKH)         |
| `x/qbtc/zk/hash.go`              | SHA-256 and pubkey-compression helpers in-circuit |
| `x/qbtc/zk/message.go`           | Claim text and BIP-137 digest                  |
| `x/qbtc/zk/bip137.go`            | Wallet signature parsing and pubkey recovery   |
| `x/qbtc/zk/zktest/`              | Local-key claim signing for tests and demos    |
| `x/qbtc/zk/setup.go`             | PLONK setup and prover                         |
| `x/qbtc/zk/verifier.go`          | Global verifier and verification               |
| `x/qbtc/zk/btc.go`               | Bitcoin address utilities                      |

### 11.2 Integration

| File                                           | Purpose                         |
| ---------------------------------------------- | ------------------------------- |
| `x/qbtc/keeper/genesis.go`                     | VK loading from genesis         |
| `x/qbtc/keeper/handle_msg_claim_with_proof.go` | On-chain claim handler          |
| `cmd/zkprover/main.go`                         | CLI proof generation tool       |
| `cmd/tss-emulator/main.go`                     | TSS signer emulator for testing |

### 11.3 Tests

| File                                                | Coverage                       |
| --------------------------------------------------- | ------------------------------ |
| `x/qbtc/zk/circuit_test.go`                         | ECDSA circuit end-to-end tests |
| `x/qbtc/zk/message_test.go`                         | Claim text, digest, signature parsing |
| `x/qbtc/zk/bip137_vectors_test.go`                  | Signatures from other implementations (`testdata/bip137_vectors.json`) |
| `x/qbtc/zk/integration_test.go`                     | Full claim flow simulation     |
| `x/qbtc/zk/security_audit_test.go`                  | Security property verification |
| `x/qbtc/keeper/handle_msg_claim_with_proof_test.go` | Handler integration tests      |

### 11.4 Protocol Buffers

| File                                            | Purpose             |
| ----------------------------------------------- | ------------------- |
| `proto/qbtc/qbtc/v1/msg_claim_with_proof.proto` | Message definitions |

---

## Appendix A: Signing the Claim

### A.1 With a Bitcoin Wallet

```bash
zkprover message --chain-id qbtc-1 --bitcoin-address bc1q... --claimer qbtc1...
# → qbtc-claim-v1|qbtc-1|bc1q...|qbtc1...
```

Sign the printed line with the wallet that holds the address ("Sign message" in Electrum or Sparrow, `bitcoin-cli signmessage` for legacy addresses, the message-signing feature of Ledger or Trezor). Then:

```bash
zkprover prove --chain-id qbtc-1 --bitcoin-address bc1q... --claimer qbtc1... \
  --utxo <txid>:<vout> --signature '<base64 from the wallet>' -o claim.json
qbtcd tx qbtc claim-with-proof claim.json --from <key>
```

Add `--receiver qbtc1...` to both commands to send the coins elsewhere. The address must be given exactly as the chain stores it on the UTXO (`qbtcd q qbtc utxo`).

### A.2 With a TSS/MPC Signer

`zkprover prove --tss-url http://host:port ...` asks the signer for a signature over the 32-byte BIP-137 digest of the claim text (printed on stderr by `zkprover message`).

**Endpoint**: `POST /sign`

**Request**: JSON object with `message_hash` field (the digest, 64 hex characters)

**Response**: JSON object with:

- `signature.r`: 32-byte scalar (big-endian hex)
- `signature.s`: 32-byte scalar (big-endian hex)
- `signature.v`: Recovery ID (0 or 1)
- `public_key`: 33-byte compressed SEC1 format (66 hex characters)

### A.3 TSS Emulator

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
- **Circuit**: `BTCPubKeyOwnershipCircuit`
- **Binding**: Hash160(compressed_pubkey) == AddressHash

#### P2WPKH (Pay-to-Witness-Public-Key-Hash)

- **Address format**: `bc1q...` (Bech32, 42 characters)
- **Script**: `OP_0 <20-byte-pubkeyHash>`
- **Circuit**: `BTCPubKeyOwnershipCircuit`
- **Binding**: Hash160(compressed_pubkey) == AddressHash

### 12.2 Not Supported

Other script types (P2TR, P2SH, P2WSH, P2PK, multisig, script-path Taproot, arbitrary P2SH) are not currently supported. `BitcoinAddressToHash160` rejects them at the API boundary.

---

## 13. Security Audit Results

### 13.1 Properties Verified

| Property                  | Status      | Test                           |
| ------------------------- | ----------- | ------------------------------ |
| **Soundness**             | ✅ Verified | Invalid proofs rejected        |
| **Zero-Knowledge**        | ✅ Verified | Signatures/keys remain private |
| **Address Binding**       | ✅ Verified | Proof bound to Bitcoin address |
| **Destination Binding**   | ✅ Verified | Front-running protection       |
| **Chain Binding**         | ✅ Verified | Cross-chain replay protection  |
| **Verifier Immutability** | ✅ Verified | VK replacement attacks blocked |

### 13.2 Attack Scenarios Tested

| Attack                           | Result                                  |
| -------------------------------- | --------------------------------------- |
| Claim someone else's address     | ❌ BLOCKED - constraint fails           |
| Invalid signature                | ❌ BLOCKED - verification fails         |
| Front-running proof interception | ❌ BLOCKED - proof bound to destination |
| Cross-chain replay               | ❌ BLOCKED - chain ID mismatch          |
| VK replacement                   | ❌ BLOCKED - verifier immutable         |

### 13.3 Test Coverage

```
x/qbtc/zk/security_audit_test.go     - Security property tests
x/qbtc/zk/circuit_test.go            - ECDSA circuit tests
x/qbtc/zk/integration_test.go        - Full flow tests
```
