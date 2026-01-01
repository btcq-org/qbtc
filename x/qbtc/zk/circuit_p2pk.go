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

// BTCP2PKCircuit is the ZK circuit that proves ownership of a P2PK (Pay-to-Public-Key)
// output. This is a legacy script type where the script contains the raw public key:
// Script: <pubkey> OP_CHECKSIG
//
// Unlike P2PKH, there's no hash of the public key - the full public key is in the script.
// This circuit is simpler because it doesn't need Hash160 computation.
//
// This is rare in modern Bitcoin but exists in early blocks (e.g., Satoshi's coins).
type BTCP2PKCircuit struct {
	// Private inputs (hidden in the proof)
	SignatureR emulated.Element[Secp256k1Fr] `gnark:",secret"`
	SignatureS emulated.Element[Secp256k1Fr] `gnark:",secret"`
	// Note: PublicKey is PRIVATE because we want to hide which specific P2PK output we're claiming
	PublicKeyX emulated.Element[Secp256k1Fp] `gnark:",secret"`
	PublicKeyY emulated.Element[Secp256k1Fp] `gnark:",secret"`

	// Public inputs (visible to verifier)
	// MessageHash is the hash of the message that was signed (32 bytes)
	MessageHash [32]frontend.Variable `gnark:",public"`
	// CompressedPubKey is the 33-byte compressed public key from the P2PK script
	CompressedPubKey [33]frontend.Variable `gnark:",public"`
	// BTCQAddressHash is the SHA256 hash of the destination address on qbtc
	BTCQAddressHash [32]frontend.Variable `gnark:",public"`
	// ChainID is a hash of the chain identifier (first 8 bytes of SHA256(chain_id))
	ChainID [8]frontend.Variable `gnark:",public"`
}

// Define implements the gnark circuit interface.
// The circuit proves:
// 1. The signature is valid for the given public key and message
// 2. The public key, when compressed, matches the claimed CompressedPubKey
func (c *BTCP2PKCircuit) Define(api frontend.API) error {
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
	// Step 2: Verify public key matches the claimed compressed pubkey
	// ========================================
	pubKeyPoint := &sw_emulated.AffinePoint[Secp256k1Fp]{
		X: c.PublicKeyX,
		Y: c.PublicKeyY,
	}

	computedCompressedPubKey := c.compressPubKeyFromPoint(api, baseField, pubKeyPoint)

	// Assert compressed pubkey matches
	for i := 0; i < 33; i++ {
		api.AssertIsEqual(computedCompressedPubKey[i], c.CompressedPubKey[i])
	}

	return nil
}

// bytesToScalar converts a byte array to a scalar field element
func (c *BTCP2PKCircuit) bytesToScalar(
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
func (c *BTCP2PKCircuit) compressPubKeyFromPoint(
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

// NewBTCP2PKCircuitPlaceholder creates an empty circuit for compilation.
func NewBTCP2PKCircuitPlaceholder() *BTCP2PKCircuit {
	return &BTCP2PKCircuit{}
}

// P2PKProofParams contains parameters for P2PK proof generation
type P2PKProofParams struct {
	SignatureR *big.Int
	SignatureS *big.Int
	PublicKeyX *big.Int
	PublicKeyY *big.Int

	MessageHash      [32]byte
	CompressedPubKey [33]byte // The compressed public key from the P2PK script
	BTCQAddressHash  [32]byte
	ChainID          [8]byte
}

// P2PKVerificationParams contains parameters for P2PK proof verification
type P2PKVerificationParams struct {
	MessageHash      [32]byte
	CompressedPubKey [33]byte // The compressed public key
	BTCQAddressHash  [32]byte
	ChainID          [8]byte
}
