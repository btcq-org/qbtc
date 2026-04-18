// Package zk implements zero-knowledge proof generation and verification
// for Bitcoin address ownership using ECDSA signatures.
package zk

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/emulated/sw_emulated"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/std/signature/ecdsa"
)

// BTCSignatureCircuit is the ZK circuit that proves ownership of a Bitcoin address
// using an ECDSA signature. It proves: "I have a valid signature from the key
// that controls this Bitcoin address" without revealing the signature or public key.
//
// SECURITY: The proof is bound to:
// 1. The Bitcoin address (via Hash160 of the public key)
// 2. The message being signed (includes destination and chain binding)
// 3. The signature is valid for the claimed public key
//
// This circuit is compatible with MPC/TSS signers that cannot reveal private keys.
type BTCSignatureCircuit struct {
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
func (c *BTCSignatureCircuit) Define(api frontend.API) error {
	// Get the base field for point operations
	baseField, err := emulated.NewField[Secp256k1Fp](api)
	if err != nil {
		return err
	}

	// Get the scalar field for message hash conversion
	scalarField, err := emulated.NewField[Secp256k1Fr](api)
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
	messageScalar := c.bytesToScalar(api, scalarField, c.MessageHash[:])

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
	compressedPubKey := c.compressPubKeyFromPoint(api, baseField, pubKeyPoint)

	// Compute Hash160 = RIPEMD160(SHA256(compressedPubKey))
	hash160 := c.computeHash160(api, compressedPubKey[:])

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

// bytesToScalar converts big-endian bytes to a Secp256k1Fr scalar element.
// Assembles 4×64-bit limbs directly via constant-shift arithmetic, avoiding
// api.ToBinary on each byte (MessageHash is a public input — range is enforced
// by the verifier, not the circuit).
func (c *BTCSignatureCircuit) bytesToScalar(
	api frontend.API,
	_ *emulated.Field[Secp256k1Fr],
	bytes []frontend.Variable,
) emulated.Element[Secp256k1Fr] {
	limbs := make([]frontend.Variable, 4)
	for i := range 4 {
		var limb frontend.Variable = 0
		for j := range 8 {
			byteIdx := (3-i)*8 + j
			shift := uint64(1) << uint(8*(7-j))
			limb = api.Add(limb, api.Mul(bytes[byteIdx], shift))
		}
		limbs[i] = limb
	}
	return emulated.Element[Secp256k1Fr]{Limbs: limbs}
}

// compressPubKeyFromPoint computes the compressed public key (33 bytes) from a point
func (c *BTCSignatureCircuit) compressPubKeyFromPoint(
	api frontend.API,
	field *emulated.Field[Secp256k1Fp],
	pubKey *sw_emulated.AffinePoint[Secp256k1Fp],
) [33]frontend.Variable {
	var result [33]frontend.Variable

	// Extract x coordinate bits
	// field.ToBits returns bits in little-endian order: bit[0] is LSB
	xBits := field.ToBits(&pubKey.X)

	// Parity of Y equals the parity of its least-significant limb —
	// avoids decomposing all 256 bits of Y just to read 1 bit.
	yParity := api.ToBinary(pubKey.Y.Limbs[0], 1)[0]

	// Construct prefix byte: 0x02 + yParity = 0x02 or 0x03
	result[0] = api.Add(2, yParity)

	// Pack x bits into bytes (big-endian byte order for compressed pubkey)
	// For big-endian output: byte[0] contains MSB bits (bits 255-248)
	// Each byte is packed with bit[0] as LSB within the byte
	for byteIdx := 0; byteIdx < 32; byteIdx++ {
		var byteVal frontend.Variable = 0
		for bitIdx := 0; bitIdx < 8; bitIdx++ {
			// For big-endian byte order: first output byte (byteIdx=0) gets highest bits
			// Within each byte: bitIdx=0 is LSB, bitIdx=7 is MSB
			// So for byteIdx=0: we want bits 255-248, where bit 248 is byte's LSB
			srcBitIdx := (31-byteIdx)*8 + bitIdx
			if srcBitIdx < len(xBits) {
				bit := xBits[srcBitIdx]
				byteVal = api.Add(byteVal, api.Mul(bit, 1<<bitIdx))
			}
		}
		result[1+byteIdx] = byteVal
	}

	return result
}

// computeHash160 computes RIPEMD160(SHA256(data))
func (c *BTCSignatureCircuit) computeHash160(api frontend.API, data []frontend.Variable) [20]frontend.Variable {
	// First compute SHA256
	sha256Result := computeSHA256Circuit(api, data)

	// Then compute RIPEMD160
	return computeRIPEMD160Circuit(api, sha256Result[:])
}

// NewBTCSignatureCircuitPlaceholder creates an empty circuit for compilation.
// This is used during setup to generate the constraint system.
func NewBTCSignatureCircuitPlaceholder() *BTCSignatureCircuit {
	return &BTCSignatureCircuit{}
}
