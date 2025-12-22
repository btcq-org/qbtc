// Package zk implements zero-knowledge proof generation and verification.
package zk

import (
	"crypto/sha256"

	"github.com/consensys/gnark/frontend"
)

// BIP-340 Tag constants for tagged hashes.
// Each tag is used as: SHA256(SHA256(tag) || SHA256(tag) || data)
const (
	// TagBIP340Challenge is used for computing the Schnorr signature challenge.
	TagBIP340Challenge = "BIP0340/challenge"
	// TagBIP340Aux is used for aux randomness in nonce generation.
	TagBIP340Aux = "BIP0340/aux"
	// TagBIP340Nonce is used for nonce generation.
	TagBIP340Nonce = "BIP0340/nonce"
	// TagTapTweak is used for taproot key tweaking.
	TagTapTweak = "TapTweak"
	// TagTapLeaf is used for tapleaf hashing.
	TagTapLeaf = "TapLeaf"
	// TagTapBranch is used for tapbranch hashing.
	TagTapBranch = "TapBranch"
	// TagTapSighash is used for taproot sighash computation.
	TagTapSighash = "TapSighash"
)

// Precomputed tag hashes for efficiency.
// These are SHA256(tag) values that can be used directly in circuits.
var (
	// TagHashBIP340Challenge = SHA256("BIP0340/challenge")
	TagHashBIP340Challenge = sha256.Sum256([]byte(TagBIP340Challenge))
	// TagHashTapTweak = SHA256("TapTweak")
	TagHashTapTweak = sha256.Sum256([]byte(TagTapTweak))
)

// TaggedHash computes BIP-340 tagged hash: SHA256(SHA256(tag) || SHA256(tag) || data)
// This is used for domain separation in BIP-340 Schnorr signatures.
func TaggedHash(tag string, data ...[]byte) [32]byte {
	tagHash := sha256.Sum256([]byte(tag))

	h := sha256.New()
	h.Write(tagHash[:])
	h.Write(tagHash[:])
	for _, d := range data {
		h.Write(d)
	}

	var result [32]byte
	copy(result[:], h.Sum(nil))
	return result
}

// TaggedHashWithPrecomputedTag computes tagged hash using a precomputed tag hash.
// More efficient when the tag hash is already known.
func TaggedHashWithPrecomputedTag(tagHash [32]byte, data ...[]byte) [32]byte {
	h := sha256.New()
	h.Write(tagHash[:])
	h.Write(tagHash[:])
	for _, d := range data {
		h.Write(d)
	}

	var result [32]byte
	copy(result[:], h.Sum(nil))
	return result
}

// computeTaggedHashCircuit computes a BIP-340 tagged hash in-circuit.
// Uses precomputed tag hash constants for efficiency.
// tagHash should be the precomputed SHA256(tag) as 32 bytes.
func computeTaggedHashCircuit(api frontend.API, tagHash [32]byte, data []frontend.Variable) [32]frontend.Variable {
	// Build the preimage: tagHash || tagHash || data
	preimage := make([]frontend.Variable, 64+len(data))

	// First copy of tag hash
	for i := 0; i < 32; i++ {
		preimage[i] = frontend.Variable(tagHash[i])
	}

	// Second copy of tag hash
	for i := 0; i < 32; i++ {
		preimage[32+i] = frontend.Variable(tagHash[i])
	}

	// Data
	for i, d := range data {
		preimage[64+i] = d
	}

	// Compute SHA256
	return computeSHA256Circuit(api, preimage)
}

// computeBIP340ChallengeCircuit computes the Schnorr signature challenge in-circuit.
// e = SHA256(SHA256("BIP0340/challenge") || SHA256("BIP0340/challenge") || R.x || P.x || m)
// Where R is the signature nonce point, P is the public key, and m is the message.
func computeBIP340ChallengeCircuit(api frontend.API, rX [32]frontend.Variable, pX [32]frontend.Variable, message [32]frontend.Variable) [32]frontend.Variable {
	// Concatenate: R.x || P.x || message (each 32 bytes = 96 bytes total)
	data := make([]frontend.Variable, 96)
	for i := 0; i < 32; i++ {
		data[i] = rX[i]
		data[32+i] = pX[i]
		data[64+i] = message[i]
	}

	return computeTaggedHashCircuit(api, TagHashBIP340Challenge, data)
}

// ComputeBIP340Challenge computes the Schnorr signature challenge outside circuit.
// e = tagged_hash("BIP0340/challenge", R.x || P.x || m)
func ComputeBIP340Challenge(rX, pX, message [32]byte) [32]byte {
	data := make([]byte, 96)
	copy(data[0:32], rX[:])
	copy(data[32:64], pX[:])
	copy(data[64:96], message[:])
	return TaggedHash(TagBIP340Challenge, data)
}

// ComputeTapTweakHash computes the taproot tweak hash.
// tweak = tagged_hash("TapTweak", P.x || merkle_root)
// If merkle_root is nil (key-path only), uses just P.x
func ComputeTapTweakHash(internalKeyX [32]byte, merkleRoot []byte) [32]byte {
	if merkleRoot == nil || len(merkleRoot) == 0 {
		return TaggedHash(TagTapTweak, internalKeyX[:])
	}
	return TaggedHash(TagTapTweak, internalKeyX[:], merkleRoot)
}
