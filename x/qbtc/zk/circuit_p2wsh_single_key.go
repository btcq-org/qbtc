// Package zk implements zero-knowledge proof generation and verification
// for Bitcoin address ownership using ECDSA signatures.
package zk

import (
	"math/big"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/emulated/sw_emulated"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/std/signature/ecdsa"
)

// BTCP2WSHSingleKeyCircuit is the ZK circuit that proves ownership of a P2WSH
// (Pay-to-Witness-Script-Hash) address where the witness script is a single-key
// script: <pubkey> OP_CHECKSIG
//
// The witness script format is: 0x21 || compressed_pubkey (33 bytes) || 0xAC
// Where: 0x21 = OP_PUSHBYTES_33, 0xAC = OP_CHECKSIG
// Total script length: 35 bytes
//
// The P2WSH address encodes: SHA256(witness_script)
//
// This circuit proves:
// 1. Valid ECDSA signature for the public key
// 2. SHA256(0x21 || compressed_pubkey || 0xAC) equals the claimed witness program
type BTCP2WSHSingleKeyCircuit struct {
	// Private inputs (hidden in the proof)
	SignatureR emulated.Element[Secp256k1Fr] `gnark:",secret"`
	SignatureS emulated.Element[Secp256k1Fr] `gnark:",secret"`
	PublicKeyX emulated.Element[Secp256k1Fp] `gnark:",secret"`
	PublicKeyY emulated.Element[Secp256k1Fp] `gnark:",secret"`

	// Public inputs (visible to verifier)
	// MessageHash is the hash of the message that was signed (32 bytes)
	MessageHash [32]frontend.Variable `gnark:",public"`
	// WitnessProgram is the SHA256 of the witness script (32 bytes)
	// This is what's encoded in the bc1q... address (62 chars for P2WSH)
	WitnessProgram [32]frontend.Variable `gnark:",public"`
	// BTCQAddressHash is the SHA256 hash of the destination address on qbtc
	BTCQAddressHash [32]frontend.Variable `gnark:",public"`
	// ChainID is a hash of the chain identifier (first 8 bytes of SHA256(chain_id))
	ChainID [8]frontend.Variable `gnark:",public"`
}

// Define implements the gnark circuit interface.
// The circuit proves:
// 1. The signature is valid for the given public key and message
// 2. SHA256(0x21 || compressed_pubkey || 0xAC) == WitnessProgram
func (c *BTCP2WSHSingleKeyCircuit) Define(api frontend.API) error {
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
	// Step 1: Verify ECDSA signature
	// ========================================
	pubKey := ecdsa.PublicKey[Secp256k1Fp, Secp256k1Fr]{
		X: c.PublicKeyX,
		Y: c.PublicKeyY,
	}

	sig := &ecdsa.Signature[Secp256k1Fr]{
		R: c.SignatureR,
		S: c.SignatureS,
	}

	messageScalar := c.bytesToScalar(api, scalarField, c.MessageHash[:])
	pubKey.Verify(api, sw_emulated.GetSecp256k1Params(), &messageScalar, sig)

	// ========================================
	// Step 2: Build the witness script and compute its hash
	// ========================================
	// Witness script format: 0x21 || compressed_pubkey || 0xAC
	// 0x21 = OP_PUSHBYTES_33 (push 33 bytes)
	// 0xAC = OP_CHECKSIG

	pubKeyPoint := &sw_emulated.AffinePoint[Secp256k1Fp]{
		X: c.PublicKeyX,
		Y: c.PublicKeyY,
	}

	compressedPubKey := c.compressPubKeyFromPoint(api, baseField, pubKeyPoint)

	// Build the witness script (35 bytes total)
	witnessScript := make([]frontend.Variable, 35)
	witnessScript[0] = frontend.Variable(0x21) // OP_PUSHBYTES_33
	for i := 0; i < 33; i++ {
		witnessScript[1+i] = compressedPubKey[i]
	}
	witnessScript[34] = frontend.Variable(0xAC) // OP_CHECKSIG

	// Compute SHA256 of the witness script
	expectedWitnessProgram := computeSHA256Circuit(api, witnessScript)

	// Assert witness program matches
	for i := 0; i < 32; i++ {
		api.AssertIsEqual(expectedWitnessProgram[i], c.WitnessProgram[i])
	}

	return nil
}

// bytesToScalar converts a byte array to a scalar field element
func (c *BTCP2WSHSingleKeyCircuit) bytesToScalar(
	api frontend.API,
	field *emulated.Field[Secp256k1Fr],
	bytes []frontend.Variable,
) emulated.Element[Secp256k1Fr] {
	bits := make([]frontend.Variable, len(bytes)*8)
	for i, b := range bytes {
		byteBits := api.ToBinary(b, 8)
		for j := 0; j < 8; j++ {
			bits[i*8+j] = byteBits[7-j]
		}
	}

	limbSize := 64
	numLimbs := 4
	limbs := make([]frontend.Variable, numLimbs)

	for limbIdx := 0; limbIdx < numLimbs; limbIdx++ {
		limbBits := make([]frontend.Variable, limbSize)
		for bitIdx := 0; bitIdx < limbSize; bitIdx++ {
			globalBitIdx := (numLimbs-1-limbIdx)*limbSize + (limbSize - 1 - bitIdx)
			if globalBitIdx < len(bits) {
				limbBits[bitIdx] = bits[globalBitIdx]
			} else {
				limbBits[bitIdx] = 0
			}
		}
		limbs[limbIdx] = api.FromBinary(limbBits...)
	}

	return emulated.Element[Secp256k1Fr]{
		Limbs: limbs,
	}
}

// compressPubKeyFromPoint computes the compressed public key (33 bytes) from a point
func (c *BTCP2WSHSingleKeyCircuit) compressPubKeyFromPoint(
	api frontend.API,
	field *emulated.Field[Secp256k1Fp],
	pubKey *sw_emulated.AffinePoint[Secp256k1Fp],
) [33]frontend.Variable {
	var result [33]frontend.Variable

	xBits := field.ToBits(&pubKey.X)
	yBits := field.ToBits(&pubKey.Y)
	yParity := yBits[0]

	result[0] = api.Add(2, yParity)

	for byteIdx := 0; byteIdx < 32; byteIdx++ {
		var byteVal frontend.Variable = 0
		for bitIdx := 0; bitIdx < 8; bitIdx++ {
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

// NewBTCP2WSHSingleKeyCircuitPlaceholder creates an empty circuit for compilation.
func NewBTCP2WSHSingleKeyCircuitPlaceholder() *BTCP2WSHSingleKeyCircuit {
	return &BTCP2WSHSingleKeyCircuit{}
}

// P2WSHSingleKeyProofParams contains parameters for P2WSH single-key proof generation
type P2WSHSingleKeyProofParams struct {
	SignatureR *big.Int
	SignatureS *big.Int
	PublicKeyX *big.Int
	PublicKeyY *big.Int

	MessageHash     [32]byte
	WitnessProgram  [32]byte // SHA256 of the witness script
	BTCQAddressHash [32]byte
	ChainID         [8]byte
}

// P2WSHSingleKeyVerificationParams contains parameters for P2WSH single-key proof verification
type P2WSHSingleKeyVerificationParams struct {
	MessageHash     [32]byte
	WitnessProgram  [32]byte // SHA256 of the witness script
	BTCQAddressHash [32]byte
	ChainID         [8]byte
}
