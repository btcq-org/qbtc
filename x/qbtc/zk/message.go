package zk

import (
	"crypto/sha256"
)

// ClaimMessageVersion is the version string included in the claim message
// to ensure forward compatibility and prevent cross-version replay attacks.
const ClaimMessageVersion = "qbtc-claim-v1"

// Type prefixes for domain separation - prevents cross-type replay attacks
// where a script hash might equal a pubkey hash by chance.
const (
	TypePrefixECDSA   = "ecdsa:"   // P2PKH, P2WPKH
	TypePrefixSchnorr = "schnorr:" // P2TR
	TypePrefixP2SH    = "p2sh:"    // P2SH-P2WPKH
	TypePrefixP2PK    = "p2pk:"    // P2PK
	TypePrefixP2WSH   = "p2wsh:"   // P2WSH single-key
)

// ComputeClaimMessage computes the deterministic message hash for a claim.
// This message is what needs to be signed by the TSS signer.
//
// The message format is:
//
//	SHA256("ecdsa:" || AddressHash || BTCQAddressHash || ChainID || "qbtc-claim-v1")
//
// This binds the signature to:
//   - The script type (prevents cross-type replay)
//   - The Bitcoin address being claimed (AddressHash)
//   - The destination qbtc address (BTCQAddressHash)
//   - The chain ID (prevents cross-chain replay)
//   - A version string (prevents cross-version replay)
func ComputeClaimMessage(addressHash [20]byte, btcqAddressHash [32]byte, chainID [8]byte) [32]byte {
	// Concatenate all components with type prefix
	prefix := []byte(TypePrefixECDSA)
	data := make([]byte, 0, len(prefix)+20+32+8+len(ClaimMessageVersion))
	data = append(data, prefix...)
	data = append(data, addressHash[:]...)
	data = append(data, btcqAddressHash[:]...)
	data = append(data, chainID[:]...)
	data = append(data, []byte(ClaimMessageVersion)...)

	// Hash the concatenation
	return sha256.Sum256(data)
}

// ComputeClaimMessageFromStrings is a convenience function that computes the
// claim message from string inputs. It's useful for CLI tools.
func ComputeClaimMessageFromStrings(addressHashHex string, btcqAddress string, chainID string) ([32]byte, error) {
	var result [32]byte

	// Parse address hash
	addressHash, err := AddressHashFromHex(addressHashHex)
	if err != nil {
		return result, err
	}

	// Hash the btcq address
	btcqAddressHash := HashBTCQAddress(btcqAddress)

	// Hash the chain ID
	chainIDHash := ComputeChainIDHash(chainID)

	return ComputeClaimMessage(addressHash, btcqAddressHash, chainIDHash), nil
}

// VerifyClaimMessage checks that a message hash matches the expected claim message.
// This is used by the verifier to ensure the proof is bound to the correct parameters.
func VerifyClaimMessage(messageHash [32]byte, addressHash [20]byte, btcqAddressHash [32]byte, chainID [8]byte) bool {
	expected := ComputeClaimMessage(addressHash, btcqAddressHash, chainID)
	return messageHash == expected
}

// ComputeClaimMessageForSchnorr computes the claim message for a Taproot (Schnorr) proof.
// Uses the x-only public key (32 bytes) instead of Hash160.
//
// Message format:
//
//	SHA256("schnorr:" || XOnlyPubKey || BTCQAddressHash || ChainID || "qbtc-claim-v1")
func ComputeClaimMessageForSchnorr(xOnlyPubKey [32]byte, btcqAddressHash [32]byte, chainID [8]byte) [32]byte {
	prefix := []byte(TypePrefixSchnorr)
	data := make([]byte, 0, len(prefix)+32+32+8+len(ClaimMessageVersion))
	data = append(data, prefix...)
	data = append(data, xOnlyPubKey[:]...)
	data = append(data, btcqAddressHash[:]...)
	data = append(data, chainID[:]...)
	data = append(data, []byte(ClaimMessageVersion)...)
	return sha256.Sum256(data)
}

// ComputeClaimMessageForP2SH computes the claim message for a P2SH-P2WPKH proof.
// Uses the script hash (20 bytes) as the address identifier.
//
// Message format:
//
//	SHA256("p2sh:" || ScriptHash || BTCQAddressHash || ChainID || "qbtc-claim-v1")
func ComputeClaimMessageForP2SH(scriptHash [20]byte, btcqAddressHash [32]byte, chainID [8]byte) [32]byte {
	prefix := []byte(TypePrefixP2SH)
	data := make([]byte, 0, len(prefix)+20+32+8+len(ClaimMessageVersion))
	data = append(data, prefix...)
	data = append(data, scriptHash[:]...)
	data = append(data, btcqAddressHash[:]...)
	data = append(data, chainID[:]...)
	data = append(data, []byte(ClaimMessageVersion)...)
	return sha256.Sum256(data)
}

// ComputeClaimMessageForP2PK computes the claim message for a P2PK proof.
// Uses the compressed public key (33 bytes) as the identifier.
//
// Message format:
//
//	SHA256("p2pk:" || CompressedPubKey || BTCQAddressHash || ChainID || "qbtc-claim-v1")
func ComputeClaimMessageForP2PK(compressedPubKey [33]byte, btcqAddressHash [32]byte, chainID [8]byte) [32]byte {
	prefix := []byte(TypePrefixP2PK)
	data := make([]byte, 0, len(prefix)+33+32+8+len(ClaimMessageVersion))
	data = append(data, prefix...)
	data = append(data, compressedPubKey[:]...)
	data = append(data, btcqAddressHash[:]...)
	data = append(data, chainID[:]...)
	data = append(data, []byte(ClaimMessageVersion)...)
	return sha256.Sum256(data)
}

// ComputeClaimMessageForP2WSH computes the claim message for a P2WSH single-key proof.
// Uses the witness program (32-byte SHA256 of the witness script) as the identifier.
//
// Message format:
//
//	SHA256("p2wsh:" || WitnessProgram || BTCQAddressHash || ChainID || "qbtc-claim-v1")
func ComputeClaimMessageForP2WSH(witnessProgram [32]byte, btcqAddressHash [32]byte, chainID [8]byte) [32]byte {
	prefix := []byte(TypePrefixP2WSH)
	data := make([]byte, 0, len(prefix)+32+32+8+len(ClaimMessageVersion))
	data = append(data, prefix...)
	data = append(data, witnessProgram[:]...)
	data = append(data, btcqAddressHash[:]...)
	data = append(data, chainID[:]...)
	data = append(data, []byte(ClaimMessageVersion)...)
	return sha256.Sum256(data)
}
