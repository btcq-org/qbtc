package zk

import (
	"crypto/sha256"
)

// ClaimMessageVersion is the version string included in the claim message
// to ensure forward compatibility and prevent cross-version replay attacks.
const ClaimMessageVersion = "qbtc-claim-v1"

// ClaimTagECDSAHash160 is the domain-separation prefix for claims proved by
// the BTCPubKeyOwnershipCircuit: ECDSA signature over a Hash160 pubkey
// commitment (covers P2PKH and P2WPKH). A future circuit over a different
// pubkey commitment shape — e.g. Schnorr + x-only for Taproot, or ECDSA over
// a script hash for P2SH/P2WSH — must use a distinct tag to prevent
// cross-circuit replay.
const ClaimTagECDSAHash160 = "ecdsa-hash160:"

// ComputeClaimMessage computes the deterministic message hash for a claim.
// This message is what needs to be signed by the TSS signer.
//
// The message format is:
//
//	SHA256("ecdsa-hash160:" || AddressHash || QBTCAddressHash || ChainID || "qbtc-claim-v1")
//
// This binds the signature to:
//   - The circuit family (prevents cross-circuit replay)
//   - The Bitcoin address being claimed (AddressHash)
//   - The destination qbtc address (QBTCAddressHash)
//   - The chain ID (prevents cross-chain replay)
//   - A version string (prevents cross-version replay)
func ComputeClaimMessage(addressHash [20]byte, qbtcAddressHash [32]byte, chainID [8]byte) [32]byte {
	prefix := []byte(ClaimTagECDSAHash160)
	data := make([]byte, 0, len(prefix)+20+32+8+len(ClaimMessageVersion))
	data = append(data, prefix...)
	data = append(data, addressHash[:]...)
	data = append(data, qbtcAddressHash[:]...)
	data = append(data, chainID[:]...)
	data = append(data, []byte(ClaimMessageVersion)...)

	// Hash the concatenation
	return sha256.Sum256(data)
}

// VerifyClaimMessage checks that a message hash matches the expected claim message.
// This is used by the verifier to ensure the proof is bound to the correct parameters.
func VerifyClaimMessage(messageHash [32]byte, addressHash [20]byte, qbtcAddressHash [32]byte, chainID [8]byte) bool {
	expected := ComputeClaimMessage(addressHash, qbtcAddressHash, chainID)
	return messageHash == expected
}

