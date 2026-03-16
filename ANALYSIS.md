# QBTC Blockchain - Deep Analysis

## Project Overview

QBTC is a **Cosmos SDK + CometBFT blockchain** that lets Bitcoin holders claim tokens by proving BTC address ownership via **zero-knowledge proofs (PLONK)**. It's not a general-purpose transfer chain — it's specifically designed for Bitcoin UTXO claims.

---

## How Signing Works

QBTC uses a **dual signing model**:

### 1. ZK Proof-Based Signing (for UTXO claims)

Instead of traditional on-chain signature verification, users prove Bitcoin address ownership via PLONK ZK proofs. The flow:

```
Bitcoin Holder → TSS/Wallet signs a claim message → ZK Prover generates PLONK proof → Submit proof on-chain
```

**Supported Bitcoin signature schemes:**

- **ECDSA (secp256k1)**: P2PKH, P2WPKH, P2SH-P2WPKH, P2PK, P2WSH
- **Schnorr (BIP-340)**: P2TR (Taproot)

**Message format:** `SHA256(TypePrefix || AddressHash || QBTCAddressHash || ChainID || "qbtc-claim-v1")`

Type prefixes: `ecdsa:`, `schnorr:`, `p2sh:`, `p2pk:`, `p2wsh:` — prevents cross-type attacks.

The proof binds to: the Bitcoin address, the QBTC destination address, and the chain ID (anti-replay, anti-frontrunning).

### 2. Standard Cosmos SDK Signing (for system txs)

Regular Cosmos ante handlers (`SigVerificationDecorator`) handle standard transactions like governance, staking, and **bank sends**. Supports `SIGN_MODE_DIRECT` and `SIGN_MODE_TEXTUAL`.

---

## How to Send QBTC to Other Wallets

There are **two ways** tokens move in QBTC:

### A. Standard Cosmos Bank Send (wallet-to-wallet)

The bank module IS included (`app_config.go`), so standard transfers work:

```bash
qbtcd tx bank send <from_key> <to_address> <amount>ubqbtc --chain-id qbtc-1
```

### B. Claim UTXOs with ZK Proof (minting new tokens)

This is the primary mechanism — claims Bitcoin UTXOs and mints QBTC:

```bash
# Step 1: Generate ZK proof via zkprover CLI
zkprover prove \
  --tss-url http://localhost:8080 \
  --qbtc-address qbtc1... \
  --chain-id qbtc-1 \
  --address-hash <Hash160> \
  --setup-dir ./zk-setup

# Step 2: Submit claim
qbtcd tx qbtc claim-with-proof \
  --claimer qbtc1... \
  --utxos '[{"txid":"...","vout":0}]' \
  --proof <hex_proof> \
  --message-hash <hex> \
  --address-hash <hex> \
  --qbtc-address-hash <hex> \
  --from <key_name>
```

### C. Bitcoin OP_RETURN Claim

Users can also claim by sending a Bitcoin transaction with an `OP_RETURN` memo in format `claim:<qbtc_address>`. Validators process this via `MsgReportBlock`.

---

## CLI Commands

**Binary:** `qbtcd` (built via `make build`)

| Command                          | Purpose                          |
| -------------------------------- | -------------------------------- |
| `tx bank send`                   | Transfer QBTC between wallets    |
| `tx qbtc claim-with-proof`       | Claim UTXOs with ZK proof        |
| `tx qbtc gov-claim-utxo`         | Governance UTXO claim            |
| `tx qbtc report-block`           | Validator reports Bitcoin block   |
| `tx qbtc set-node-peer-address`  | Set validator P2P address         |
| `tx qbtc update-param`           | Governance param update           |
| `keys add/list/show`             | Key management                   |
| `query qbtc last-processed-block`| Last Bitcoin block processed     |
| `query qbtc params`              | Module parameters                |

---

## Token Economics

- Tokens are **minted** when UTXOs are claimed (not pre-minted)
- Unclaimed UTXOs go to a `reserve` module account
- `ProcessNetworkReward()` runs every block — transfers emission from reserve to `fee_collector` → distributed to stakers
- Emission formula: `reserve_balance / (EmissionCurve * BlocksPerYear)`

---

## Key Files

| Component        | Path                                                  |
| ---------------- | ----------------------------------------------------- |
| CLI entry        | `cmd/qbtcd/main.go`                                   |
| ZK prover        | `cmd/zkprover/main.go`                                 |
| Claim handler    | `x/qbtc/keeper/handle_msg_claim_with_proof.go`         |
| Token minting    | `x/qbtc/keeper/keeper_claim_utxo.go`                   |
| ZK circuits      | `x/qbtc/zk/circuit_signature.go`, `circuit_schnorr.go` |
| ZK verifier      | `x/qbtc/zk/verifier.go`                                |
| Message hashing  | `x/qbtc/zk/message.go`                                 |
| Block reporting  | `x/qbtc/keeper/handler_msg_report_block.go`             |
| Network rewards  | `x/qbtc/keeper/network_manager.go`                      |
| App config       | `app/app_config.go`                                     |
| Ante handlers    | `app/ante.go`                                           |

---

## ZK Proof System Details

- **Proof system:** PLONK with BN254 elliptic curve
- **SRS:** Hermez/Polygon Powers of Tau ceremony (2^21 constraints)
- **Proof size:** ~1KB (max 50KB enforced)
- **Private inputs:** Signature (R, S), Public Key (X, Y)
- **Public inputs:** MessageHash, AddressHash, QBTCAddressHash, ChainID
- **Batch limit:** Max 50 UTXOs per claim transaction

### Circuit Verification (in-circuit)

- ECDSA signature verification using gnark's standard gadget
- Public key compression to 33-byte format
- Hash160 computation (SHA256 → RIPEMD160) for address verification
- BIP-340 Schnorr verification with even-Y enforcement for Taproot

---

## Security Features

1. **ZK Circuit Security:** Verifying key immutable after genesis; thread-safe global verifier
2. **Message Binding:** Chain ID separation, claimer address binding, version string
3. **Proof Validation:** Size bounds (100B min, 50KB max), message hash validation before circuit verification
4. **Validator Consensus:** Bitcoin blocks require 2/3+ validator attestations by staking power
5. **Domain Separation:** Type-prefixed message hashing prevents cross-type attacks

---

## ML-DSA (Post-Quantum) Key Support

### Status: Fully supported for transaction signing

Both **secp256k1** and **ML-DSA** keys work for wallet-to-wallet transfers. The signing pipeline is algorithm-agnostic.

| Layer | Key Type | Post-Quantum? |
| ----- | -------- | ------------- |
| Validator consensus | ML-DSA (custom CometBFT fork) | Yes |
| Block attestations | ML-DSA (`VerifySignature()` is algorithm-agnostic) | Yes |
| Account tx signing (wallet-to-wallet) | secp256k1 or ML-DSA | **Yes (if ML-DSA key is used)** |
| Bitcoin ZK proofs | secp256k1 ECDSA / Schnorr | No (Bitcoin protocol limitation) |

### Does the key type matter for signing?

**No.** The forked Cosmos SDK (`github.com/btcq-org/cosmos-sdk`) handles both key types transparently:

1. **`DefaultSigVerificationGasConsumer`** (in `x/auth/ante/sigverify.go`) has a type switch:
   - `*secp256k1.PubKey` → consumes `SigVerifyCostSecp256k1` gas
   - `*ed25519.PubKey` → consumes `SigVerifyCostED25519` gas
   - `*secp256r1.PubKey` → consumes `SigVerifyCostSecp256r1` gas
   - `*mldsa.PubKey` → **consumes 0 gas** (free signature verification)

2. **`SigVerificationDecorator.AnteHandle`** calls `authsigning.VerifySignature(ctx, pubKey, ...)` which is polymorphic — it dispatches to whatever `PubKey` implementation's `VerifySignature()` method.

3. The only practical difference is **gas cost**: ML-DSA verification is currently free, secp256k1 costs gas.

### Forked dependencies

Both the Cosmos SDK and CometBFT are forks with ML-DSA baked in:
- `github.com/cosmos/cosmos-sdk` → `github.com/btcq-org/cosmos-sdk` (imports `crypto/keys/mldsa`)
- `github.com/cometbft/cometbft` → `github.com/btcq-org/cometbft` (provides `crypto/mldsa`)

### What's NOT post-quantum ready

- **Bitcoin ZK proofs**: Uses secp256k1 ECDSA / Schnorr — this is a Bitcoin protocol limitation, not a QBTC limitation

### Key files

- `x/qbtc/testutil/testhelper.go` — ML-DSA key generation helpers
- `app/ante.go` — Ante handler with algorithm-agnostic signature verification
- `app/config/tx.go` — TX signing configuration
- `bifrost/qclient/attestation.go` — Attestation signature verification
- `go.mod` — Forked Cosmos SDK + CometBFT with ML-DSA
- Forked SDK `x/auth/ante/sigverify.go` — `DefaultSigVerificationGasConsumer` with ML-DSA case

---

## Project Structure

```
qbtc/
├── cmd/
│   ├── qbtcd/              # Main chain node binary
│   ├── zkprover/            # ZK proof generation CLI
│   ├── bifrost/             # Bitcoin block monitor service
│   ├── dkls-tss/            # TSS emulator
│   ├── proof-service/       # Proof generation service
│   ├── utxo-indexer/        # UTXO indexing
│   └── tss-emulator/        # TSS testing emulator
├── app/                     # Cosmos SDK application wiring
│   ├── app.go               # App struct and initialization
│   ├── app_config.go        # Module wiring via depinject
│   ├── ante.go              # Transaction validation
│   └── post.go              # Post-tx hooks
├── x/qbtc/                  # Main blockchain module
│   ├── keeper/              # State management + handlers
│   ├── types/               # Proto-generated + custom types
│   ├── module/              # Cosmos module interface
│   ├── ebifrost/            # Embedded Bifrost integration
│   └── zk/                  # Zero-knowledge proof system
├── bifrost/                  # Bitcoin block monitoring service
├── bitcoin/                  # Bitcoin RPC client code
├── proto/                    # Protocol buffer definitions
├── common/                   # Shared utilities
├── constants/                # Chain constants
└── scripts/                  # Utility scripts
```

---

## Vultisig iOS - QBTC/MLDSA Signing Analysis

### Current State: Already Implemented (Standalone)

QBTC signing in vultisig-ios **already exists** and uses a **standalone implementation** — it does NOT use WalletCore for image hash generation or transaction compilation. This is by design because WalletCore's `TransactionCompiler` assumes secp256k1 keys and cannot handle ML-DSA.

### Can we use WalletCore for QBTC?

**No.** WalletCore is incompatible with ML-DSA for three reasons:

1. **`TransactionCompiler.preImageHashes()`** — internally builds a `CosmosSigningInput` that assumes secp256k1 public keys. ML-DSA public keys (~1,312 bytes for MLDSA-44) would fail WalletCore's key validation.

2. **`TransactionCompiler.compileWithSignatures()`** — expects a 64-byte ECDSA signature (r,s) + recovery ID. ML-DSA signatures are ~2,420 bytes.

3. **`PublicKey.verify(signature:, message:)`** — WalletCore only supports secp256k1, ed25519, and secp256r1 verification. No ML-DSA support.

The standalone implementation in `QBTCHelper.swift` is the correct approach.

### How Standard Cosmos Chains Sign (WalletCore path)

```
CosmosHelperStruct.getPreSignedInputData()
  → Build CosmosSigningInput protobuf (pubkey, accountNumber, sequence, messages, fee)
  → Serialize to Data
  → TransactionCompiler.preImageHashes(coinType: .cosmos, txInputData:)
  → Returns TxCompilerPreSigningOutput.dataHash (SHA256 of SignDoc)
  → [hash.hexString]

CosmosHelperStruct.getSignedTransaction()
  → Get preImageHashes again
  → Get ECDSA signature from TssKeysignResponse (r, s, recoveryID)
  → PublicKey.verify(signature:, message:) — secp256k1 verification
  → TransactionCompiler.compileWithSignatures() — assembles TxRaw
  → CosmosSigningOutput.serialized — broadcast-ready JSON
```

### How QBTC Signs (Standalone path)

```
QBTCHelper.getPreSignedImageHash()
  → buildTxComponents() — manual protobuf: TxBody + AuthInfo
  → buildSignDocFromComponents() — manual protobuf: SignDoc
  → SHA256(signDoc)
  → [hash.toHexString()]

QBTCHelper.getSignedTransaction()
  → Rebuild TxBody + AuthInfo + SignDoc
  → SHA256(signDoc) to find matching DilithiumKeysignResponse
  → Build TxRaw(bodyBytes, authInfoBytes, mldsaSignature)
  → Base64 encode → {"tx_bytes": "...", "mode": "BROADCAST_MODE_SYNC"}
```

### Key Differences

| Aspect | Standard Cosmos (WalletCore) | QBTC (Standalone) |
| ------ | ---------------------------- | ------------------ |
| Image hash | `TransactionCompiler.preImageHashes()` | Manual `SHA256(SignDoc)` |
| Protobuf building | WalletCore's `CosmosSigningInput` | Hand-rolled protobuf encoding |
| Signature type | ECDSA (64 bytes + recovery) | ML-DSA (~2,420 bytes) |
| Tx compilation | `TransactionCompiler.compileWithSignatures()` | Manual `TxRaw` assembly |
| Sig verification | `PublicKey.verify()` (secp256k1) | None (trusted from TSS) |
| PubKey type URL | `/cosmos.crypto.secp256k1.PubKey` | `/cosmos.crypto.mldsa.PubKey` |
| Key size | 33 bytes (compressed) | ~1,312 bytes (MLDSA-44) |
| TSS library | `Tss.xcframework` / `godkls.xcframework` | `vscore.xcframework` |
| Response type | `TssKeysignResponse` (r, s) | `DilithiumKeysignResponse` (signature) |

### Routing Architecture

`CosmosHelper` (enum) acts as a router:
- `.qbtc` → dispatches to `QBTCHelper` (static methods)
- All other cases → dispatches to `CosmosHelperStruct` (WalletCore-based)

Two separate `getSignedTransaction` overloads exist in `CosmosHelper`:
- `getSignedTransaction(signatures: [String: TssKeysignResponse])` — for ECDSA chains (throws for QBTC)
- `getSignedTransaction(dilithiumSignatures: [String: DilithiumKeysignResponse])` — for QBTC only

### Key Type Routing (full signing pipeline)

```swift
// Chain.swift
chain.signingKeyType:
  .qbtc → .MLDSA
  Cosmos/EVM/UTXO/THORChain/Ripple/Tron → .ECDSA
  Solana/Polkadot/Sui/Ton/Cardano → .EdDSA

// KeysignViewModel.swift — TSS dispatch
switch keysignType {
  case .ECDSA  → DKLSKeysign (godkls/Tss framework)
  case .EdDSA  → SchnorrKeysign (goschnorr framework)
  case .MLDSA  → DilithiumKeysign (vscore framework)
}

// Vault.swift — key storage
vault.pubKeyECDSA: String        // always present
vault.pubKeyEdDSA: String        // always present
vault.publicKeyMLDSA44: String?  // optional, only for QBTC
```

### QBTC Address Derivation

```swift
// CoinFactory+QBTC.swift
Bech32("qbtc", RIPEMD160(SHA256(mldsa_pubkey_bytes)))
```

### Current Implementation Files (vultisig-ios)

| File | Purpose |
| ---- | ------- |
| `Chains/cosmos/QBTCHelper.swift` | Standalone QBTC signing (manual protobuf + SHA256) |
| `Chains/cosmos/CosmosHelper.swift` | Router — dispatches QBTC to QBTCHelper |
| `Chains/cosmos/CosmosHelperStruct.swift` | WalletCore-based signing for other Cosmos chains |
| `Chains/CoinFactory+QBTC.swift` | QBTC address generation from MLDSA key |
| `States/KeyType.swift` | `enum KeyType { case ECDSA, EdDSA, MLDSA }` |
| `States/Keysign/DilithiumKeysign.swift` | ML-DSA TSS signing via vscore |
| `States/Keygen/DilithiumKeygen.swift` | ML-DSA TSS keygen via vscore |
| `Model/Chain.swift` | `chain.signingKeyType` mapping |
| `Model/Vault.swift` | `publicKeyMLDSA44` storage |

### QBTCHelper Configuration

QBTCHelper is now instance-based with configurable chain parameters:

```swift
let helper = QBTCHelper.create()  // returns default testnet config
// Or custom:
QBTCHelper(chainID: "qbtc-1", denom: "qbtc", gasLimit: 200_000)
```

### Supported Message Type URLs

```swift
pubKeyTypeURL          = "/cosmos.crypto.mldsa.PubKey"
msgSendTypeURL         = "/cosmos.bank.v1beta1.MsgSend"
msgTransferTypeURL     = "/ibc.applications.transfer.v1.MsgTransfer"
msgVoteTypeURL         = "/cosmos.gov.v1beta1.MsgVote"
msgDelegateTypeURL     = "/cosmos.staking.v1beta1.MsgDelegate"
msgUndelegateTypeURL   = "/cosmos.staking.v1beta1.MsgUndelegate"
msgWithdrawRewardTypeURL = "/cosmos.distribution.v1beta1.MsgWithdrawDelegatorReward"
```

---

## Implementation Log: QBTC ML-DSA Signing Improvements

### What Was Implemented

#### 1. Dynamic chain config (was hardcoded static constants)
- `QBTCHelper` is now a struct with instance properties (`chainID`, `denom`, `gasLimit`)
- `QBTCHelper.create()` factory returns the default testnet config
- Easy to swap to mainnet by changing the factory or passing custom values
- `CosmosHelper` updated to use `QBTCHelper.create()` instead of static calls

#### 2. IBC Transfer support (MsgTransfer)
- Manual protobuf builder for `/ibc.applications.transfer.v1.MsgTransfer`
- Handles: source_port, source_channel, token, sender, receiver, timeout_height, timeout_timestamp
- Parses memo format `ibc:channel-N:...:optionalMemo` (same as standard Cosmos path)
- Timeout parsed from `ibcDenomTrace.height`

#### 3. Governance Vote support (MsgVote)
- Manual protobuf builder for `/cosmos.gov.v1beta1.MsgVote`
- Parses memo format `QBTC_VOTE:OPTION:PROPOSAL_ID` (compatible with DYDX_VOTE format)
- Supports: YES (1), ABSTAIN (2), NO (3), NO_WITH_VETO (4)

#### 4. Staking messages (MsgDelegate, MsgUndelegate, MsgWithdrawDelegatorReward)
- `buildDelegateAny()` — delegate tokens to a validator
- `buildUndelegateAny()` — undelegate tokens from a validator
- `buildWithdrawRewardAny()` — claim staking rewards
- All use the correct Cosmos SDK protobuf type URLs

#### 5. Transaction type routing
- `buildTxBody()` now reads `VSTransactionType` from `keysignPayload.chainSpecific`
- Routes to correct message builder based on type:
  - `.ibcTransfer` → `buildIBCTransferAny()`
  - `.vote` → `buildVoteAny()`
  - default → `buildMsgSendAny()`

#### 6. Proto encoding made internal (was private)
- `Data` extensions (`appendProtoVarint`, `appendProtoBytes`, `appendProtoString`, `appendVarint`) are now `internal` instead of `private` for potential reuse
- `QBTCProtoBuilder.buildTxRaw()` extracted as a shared utility

### Critical Bug Fix: ML-DSA signs raw bytes, not SHA256 hash

The original implementation was computing `SHA256(SignDoc)` and signing that 32-byte hash. But ML-DSA's `VerifySignature()` on the chain verifies against the **raw SignDoc bytes** — it does NOT internally hash the message.

**Root cause:** secp256k1's `VerifySignature(msg, sig)` internally calls `crypto.SHA256(msg)` before ECDSA verification. So the standard Cosmos flow works: app signs `SHA256(SignDoc)`, chain re-computes `SHA256(SignDoc)` and verifies. But ML-DSA's `VerifySignature(msg, sig)` calls `scheme.Verify(publicKey, msg, sig, nil)` directly — no hashing.

**Chain-side code** (forked SDK `crypto/keys/mldsa/mldsa.go`):
```go
func (m *PubKey) VerifySignature(msg, sig []byte) bool {
    scheme := mldsa44.Scheme()
    publicKey, _ := scheme.UnmarshalBinaryPublicKey(m.Key)
    return scheme.Verify(publicKey, msg, sig, nil)  // raw msg, NO hashing
}
```

vs secp256k1:
```go
func (pubKey *PubKey) VerifySignature(msg, sigStr []byte) bool {
    return secp256k1.VerifySignature(pubKey.Bytes(), crypto.Sha256(msg), sigStr)
    //                                                ^^^^^^^^^^^^^^^^  hashes msg
}
```

**Fix applied:** `getPreSignedImageHash()` now returns `signDoc.toHexString()` (raw bytes) instead of `signDoc.sha256().toHexString()`. The signature lookup key in `getSignedTransaction()` was updated to match.

### What Was NOT Implemented (and why)

- **Local ML-DSA verification**: The `vscore` framework does NOT expose an `mldsa_verify()` function. Only keygen and signing are available. Adding verification would require extending the Go library.
- **SignAmino support**: QBTC uses SIGN_MODE_DIRECT only. No known need for Amino JSON signing.
- **SwiftProtobuf migration**: The hand-rolled encoding is correct for proto3 wire format and keeps the dependency footprint small. Not worth adding a dependency for this.
