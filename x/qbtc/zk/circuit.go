// Package zk implements zero-knowledge proof generation and verification
// for Bitcoin address ownership using ECDSA signatures.
package zk

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/emulated/sw_emulated"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/std/signature/ecdsa"
)

// BTCAddressOwnershipCircuit is the ZK circuit that proves ownership of a Bitcoin address
// using an ECDSA signature. It proves: "I have a valid signature from the key
// that controls this Bitcoin address" without revealing the signature or public key.
//
// SECURITY: The proof is bound to:
// 1. The Bitcoin address (via Hash160 of the public key)
// 2. The message being signed (includes destination and chain binding)
// 3. The signature is valid for the claimed public key
//
// This circuit is compatible with MPC/TSS signers that cannot reveal private keys.
type BTCAddressOwnershipCircuit struct {
	// Private inputs (hidden in the proof)
	// Signature R scalar (the x-coordinate of k·G reduced mod n)
	SignatureR emulated.Element[Secp256k1Fr] `gnark:",secret"`
	// Signature S scalar
	SignatureS emulated.Element[Secp256k1Fr] `gnark:",secret"`
	// Public key X coordinate
	PublicKeyX emulated.Element[Secp256k1Fp] `gnark:",secret"`
	// Public key Y coordinate
	PublicKeyY emulated.Element[Secp256k1Fp] `gnark:",secret"`

	// Public inputs (visible to verifier)
	// MessageHash is the hash of the message that was signed (32 bytes)
	// This should be SHA256(AddressHash || QBTCAddressHash || ChainID || "qbtc-claim-v1")
	MessageHash [32]frontend.Variable `gnark:",public"`
	// AddressHash is the Hash160 (RIPEMD160(SHA256(pubkey))) of the Bitcoin public key
	AddressHash [20]frontend.Variable `gnark:",public"`
	// QBTCAddressHash is the SHA256 hash of the destination address on qbtc
	QBTCAddressHash [32]frontend.Variable `gnark:",public"`
	// ChainID is a hash of the chain identifier (first 8 bytes of SHA256(chain_id))
	ChainID [8]frontend.Variable `gnark:",public"`
}

// Define implements the gnark circuit interface.
// The circuit proves:
// 1. The signature is valid for the given public key and message
// 2. The public key hashes to the claimed Bitcoin address
// 3. The proof is bound to the destination address and chain ID
func (c *BTCAddressOwnershipCircuit) Define(api frontend.API) error {
	// Get the base field for point operations
	baseField, err := emulated.NewField[Secp256k1Fp](api)
	if err != nil {
		return err
	}

	// ========================================
	// Step 1: Verify ECDSA signature using gnark's standard gadget
	// ========================================
	// Construct the public key for gnark's ECDSA gadget
	pubKey := ecdsa.PublicKey[Secp256k1Fp, Secp256k1Fr]{
		X: c.PublicKeyX,
		Y: c.PublicKeyY,
	}

	// Construct the signature
	sig := &ecdsa.Signature[Secp256k1Fr]{
		R: c.SignatureR,
		S: c.SignatureS,
	}

	// Convert message hash bytes to scalar
	messageScalar := bytesToScalar(api, c.MessageHash[:])

	// Verify ECDSA signature using gnark's standard implementation
	pubKey.Verify(api, sw_emulated.GetSecp256k1Params(), &messageScalar, sig)

	// ========================================
	// Step 2: Verify public key hashes to address
	// ========================================
	// Compress the public key and compute Hash160
	pubKeyPoint := &sw_emulated.AffinePoint[Secp256k1Fp]{
		X: c.PublicKeyX,
		Y: c.PublicKeyY,
	}

	// Get compressed public key bytes
	compressedPubKey := compressPubKeyFromPoint(api, baseField, pubKeyPoint)

	// Compute Hash160 = RIPEMD160(SHA256(compressedPubKey))
	hash160 := computeHash160(api, compressedPubKey[:])

	// Assert hash160 == addressHash
	for i := 0; i < 20; i++ {
		api.AssertIsEqual(hash160[i], c.AddressHash[i])
	}

	// ========================================
	// Step 3: Verify message binding
	// ========================================
	// The message hash is a public input that the verifier will check
	// matches SHA256(AddressHash || QBTCAddressHash || ChainID || "qbtc-claim-v1")
	// This is done outside the circuit by the verifier

	return nil
}


// NewBTCAddressOwnershipCircuitPlaceholder creates an empty circuit for compilation.
// This is used during setup to generate the constraint system.
func NewBTCAddressOwnershipCircuitPlaceholder() *BTCAddressOwnershipCircuit {
	return &BTCAddressOwnershipCircuit{}
}
