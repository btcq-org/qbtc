// Package zk implements zero-knowledge proof generation and verification
// for Bitcoin pubkey ownership using ECDSA signatures. The 20-byte Bitcoin
// address binding (Hash160 = RIPEMD160 ∘ SHA256) is completed natively by
// the verifier; see Verifier.VerifyProof.
package zk

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/emulated/sw_emulated"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/std/signature/ecdsa"
)

// BTCPubKeyOwnershipCircuit is the ZK circuit that proves ownership of a
// Bitcoin secp256k1 public key via an ECDSA signature, without revealing the
// signature or the pubkey itself. It commits to SHA256(SEC-compressed pubkey);
// the verifier natively applies RIPEMD160 to recover the Bitcoin AddressHash
// and complete the Hash160 binding.
//
// Name: the circuit alone proves *pubkey* ownership (ECDSA sig + SHA256
// commitment). The *address* binding (RIPEMD160 step) lives outside the
// circuit, so "PubKeyOwnership" is the honest scope. Together with the
// verifier's native RIPEMD160 check, the system proves Bitcoin address
// ownership end-to-end.
//
// SECURITY: The proof is bound to:
//  1. PubKeyHashSHA256 = SHA256(SEC-compressed pubkey) (public input). The
//     verifier natively checks RIPEMD160(PubKeyHashSHA256) equals the claimed
//     20-byte Bitcoin AddressHash.
//  2. The message being signed (includes destination and chain binding).
//  3. The signature is valid for the claimed public key.
//
// This circuit is compatible with MPC/TSS signers that cannot reveal private keys.
//
// RIPEMD160 is intentionally NOT computed in-circuit; it runs natively in the
// verifier. Moving it out roughly halves prover time without weakening soundness
// (RIPEMD160 is collision-resistant, so Hash160 = RIPEMD160 ∘ SHA256 binds the
// pubkey just as tightly whether RIPEMD160 is inside or outside the SNARK).
type BTCPubKeyOwnershipCircuit struct {
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
	// MessageHash is the hash of the message that was signed (32 bytes).
	// The verifier natively re-derives this from (AddressHash, QBTCAddressHash, ChainID, version).
	MessageHash [32]frontend.Variable `gnark:",public"`
	// PubKeyHashSHA256 is SHA256 of the 33-byte SEC-compressed public key.
	// The verifier natively applies RIPEMD160 to this value and compares against
	// the claimed 20-byte Bitcoin AddressHash, completing the Hash160 binding.
	PubKeyHashSHA256 [32]frontend.Variable `gnark:",public"`
}

// Define implements the gnark circuit interface.
// The circuit proves:
//  1. The signature is valid for the given public key and message.
//  2. SHA256 of the SEC-compressed public key equals PubKeyHashSHA256.
//     (RIPEMD160 of PubKeyHashSHA256 vs. the Bitcoin AddressHash is checked
//     natively by the verifier.)
//  3. The proof is bound to the destination address and chain ID via
//     MessageHash, which the verifier re-derives natively.
func (c *BTCPubKeyOwnershipCircuit) Define(api frontend.API) error {
	// Get the base field for point operations
	baseField, err := emulated.NewField[Secp256k1Fp](api)
	if err != nil {
		return err
	}

	// ========================================
	// Step 1: Verify ECDSA signature using gnark's standard gadget
	// ========================================
	pubKey := ecdsa.PublicKey[Secp256k1Fp, Secp256k1Fr]{
		X: c.PublicKeyX,
		Y: c.PublicKeyY,
	}
	sig := &ecdsa.Signature[Secp256k1Fr]{
		R: c.SignatureR,
		S: c.SignatureS,
	}
	messageScalar := bytesToScalar(api, c.MessageHash[:])
	pubKey.Verify(api, sw_emulated.GetSecp256k1Params(), &messageScalar, sig)

	// ========================================
	// Step 2: Bind the public key to PubKeyHashSHA256
	// ========================================
	// SEC-compressed encoding is produced off-circuit by a hint and then
	// fully constrained against (PublicKeyX, PublicKeyY) — see compressPubKeyFromPoint.
	pubKeyPoint := &sw_emulated.AffinePoint[Secp256k1Fp]{
		X: c.PublicKeyX,
		Y: c.PublicKeyY,
	}
	compressedPubKey := compressPubKeyFromPoint(api, baseField, pubKeyPoint)

	sha256Result := computeSHA256Circuit(api, compressedPubKey[:])
	for i := 0; i < 32; i++ {
		api.AssertIsEqual(sha256Result[i], c.PubKeyHashSHA256[i])
	}

	// ========================================
	// Step 3: Message binding is checked natively by the verifier
	// ========================================

	return nil
}

// NewBTCPubKeyOwnershipCircuitPlaceholder creates an empty circuit for compilation.
// This is used during setup to generate the constraint system.
func NewBTCPubKeyOwnershipCircuitPlaceholder() *BTCPubKeyOwnershipCircuit {
	return &BTCPubKeyOwnershipCircuit{}
}
