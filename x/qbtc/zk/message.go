package zk

import (
	"crypto/sha256"
)

// ClaimMessageVersion is the version string included in the claim message
// to ensure forward compatibility and prevent cross-version replay attacks.
const ClaimMessageVersion = "qbtc-claim-v1"

// ComputeClaimMessage computes the deterministic message hash for a claim.
// This message is what needs to be signed by the TSS signer.
//
// The message format is:
//
//	SHA256(AddressHash || BTCQAddressHash || ChainID || "qbtc-claim-v1")
//
// This binds the signature to:
//   - The Bitcoin address being claimed (AddressHash)
//   - The destination qbtc address (BTCQAddressHash)
//   - The chain ID (prevents cross-chain replay)
//   - A version string (prevents cross-version replay)
func ComputeClaimMessage(addressHash [20]byte, btcqAddressHash [32]byte, chainID [8]byte) [32]byte {
	// Concatenate all components
	data := make([]byte, 0, 20+32+8+len(ClaimMessageVersion))
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

