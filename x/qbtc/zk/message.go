package zk

import (
	"crypto/sha256"
)

// ClaimMessageVersion is the version string included in the claim message
// to ensure forward compatibility and prevent cross-version replay attacks.
const ClaimMessageVersion = "qbtc-claim-v1"

// TypePrefixECDSA is the domain-separation prefix for ECDSA-based claims
// (P2PKH, P2WPKH). Kept as a constant so future script types added back can
// reuse the prefix-based separation scheme without reinventing it.
const TypePrefixECDSA = "ecdsa:"

// ComputeClaimMessage computes the deterministic message hash for a claim.
// This message is what needs to be signed by the TSS signer.
//
// The message format is:
//
//	SHA256("ecdsa:" || AddressHash || QBTCAddressHash || ChainID || "qbtc-claim-v1")
//
// This binds the signature to:
//   - The script type (prevents cross-type replay)
//   - The Bitcoin address being claimed (AddressHash)
//   - The destination qbtc address (QBTCAddressHash)
//   - The chain ID (prevents cross-chain replay)
//   - A version string (prevents cross-version replay)
func ComputeClaimMessage(addressHash [20]byte, qbtcAddressHash [32]byte, chainID [8]byte) [32]byte {
	// Concatenate all components with type prefix
	prefix := []byte(TypePrefixECDSA)
	data := make([]byte, 0, len(prefix)+20+32+8+len(ClaimMessageVersion))
	data = append(data, prefix...)
	data = append(data, addressHash[:]...)
	data = append(data, qbtcAddressHash[:]...)
	data = append(data, chainID[:]...)
	data = append(data, []byte(ClaimMessageVersion)...)

	// Hash the concatenation
	return sha256.Sum256(data)
}

// ComputeClaimMessageFromStrings is a convenience function that computes the
// claim message from string inputs. It's useful for CLI tools.
func ComputeClaimMessageFromStrings(addressHashHex string, qbtcAddress string, chainID string) ([32]byte, error) {
	var result [32]byte

	// Parse address hash
	addressHash, err := AddressHashFromHex(addressHashHex)
	if err != nil {
		return result, err
	}

	// Hash the btcq address
	qbtcAddressHash := HashQBTCAddress(qbtcAddress)

	// Hash the chain ID
	chainIDHash := ComputeChainIDHash(chainID)

	return ComputeClaimMessage(addressHash, qbtcAddressHash, chainIDHash), nil
}

// VerifyClaimMessage checks that a message hash matches the expected claim message.
// This is used by the verifier to ensure the proof is bound to the correct parameters.
func VerifyClaimMessage(messageHash [32]byte, addressHash [20]byte, qbtcAddressHash [32]byte, chainID [8]byte) bool {
	expected := ComputeClaimMessage(addressHash, qbtcAddressHash, chainID)
	return messageHash == expected
}

