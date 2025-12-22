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

// BTCP2SHP2WPKHCircuit is the ZK circuit that proves ownership of a P2SH-wrapped
// P2WPKH address (addresses starting with "3"). It proves:
// 1. Valid ECDSA signature for the message
// 2. Public key hashes to the correct pubkey hash
// 3. The pubkey hash, when wrapped in a P2WPKH script, hashes to the claimed script hash
//
// The P2SH-P2WPKH redeem script is: OP_0 <20-byte-pubkey-hash>
// The script hash is: Hash160(0x00 || 0x14 || pubkey_hash160)
type BTCP2SHP2WPKHCircuit struct {
	// Private inputs (hidden in the proof)
	SignatureR emulated.Element[Secp256k1Fr] `gnark:",secret"`
	SignatureS emulated.Element[Secp256k1Fr] `gnark:",secret"`
	PublicKeyX emulated.Element[Secp256k1Fp] `gnark:",secret"`
	PublicKeyY emulated.Element[Secp256k1Fp] `gnark:",secret"`

	// Public inputs (visible to verifier)
	// MessageHash is the hash of the message that was signed (32 bytes)
	MessageHash [32]frontend.Variable `gnark:",public"`
	// ScriptHash is the Hash160 of the P2SH redeem script (this IS the P2SH address payload)
	ScriptHash [20]frontend.Variable `gnark:",public"`
	// BTCQAddressHash is the SHA256 hash of the destination address on qbtc
	BTCQAddressHash [32]frontend.Variable `gnark:",public"`
	// ChainID is a hash of the chain identifier (first 8 bytes of SHA256(chain_id))
	ChainID [8]frontend.Variable `gnark:",public"`
}

// Define implements the gnark circuit interface.
// The circuit proves:
// 1. The signature is valid for the given public key and message
// 2. The public key hashes to pubkeyHash160
// 3. Hash160(0x0014 || pubkeyHash160) == ScriptHash
func (c *BTCP2SHP2WPKHCircuit) Define(api frontend.API) error {
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
	// Step 2: Compute public key hash (Hash160)
	// ========================================
	pubKeyPoint := &sw_emulated.AffinePoint[Secp256k1Fp]{
		X: c.PublicKeyX,
		Y: c.PublicKeyY,
	}

	compressedPubKey := c.compressPubKeyFromPoint(api, baseField, pubKeyPoint)
	pubkeyHash160 := c.computeHash160(api, compressedPubKey[:])

	// ========================================
	// Step 3: Compute script hash and verify
	// ========================================
	// The P2WPKH witness program is: OP_0 (0x00) + PUSH20 (0x14) + pubkeyHash160
	// Total 22 bytes
	redeemScript := make([]frontend.Variable, 22)
	redeemScript[0] = frontend.Variable(0x00) // OP_0
	redeemScript[1] = frontend.Variable(0x14) // PUSH 20 bytes
	for i := 0; i < 20; i++ {
		redeemScript[2+i] = pubkeyHash160[i]
	}

	// Compute Hash160 of the redeem script
	expectedScriptHash := c.computeHash160(api, redeemScript)

	// Assert expected script hash equals the claimed script hash
	for i := 0; i < 20; i++ {
		api.AssertIsEqual(expectedScriptHash[i], c.ScriptHash[i])
	}

	return nil
}

// bytesToScalar converts a byte array to a scalar field element
func (c *BTCP2SHP2WPKHCircuit) bytesToScalar(
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
func (c *BTCP2SHP2WPKHCircuit) compressPubKeyFromPoint(
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

// computeHash160 computes RIPEMD160(SHA256(data))
func (c *BTCP2SHP2WPKHCircuit) computeHash160(api frontend.API, data []frontend.Variable) [20]frontend.Variable {
	sha256Result := computeSHA256Circuit(api, data)
	return computeRIPEMD160Circuit(api, sha256Result[:])
}

// NewBTCP2SHP2WPKHCircuitPlaceholder creates an empty circuit for compilation.
func NewBTCP2SHP2WPKHCircuitPlaceholder() *BTCP2SHP2WPKHCircuit {
	return &BTCP2SHP2WPKHCircuit{}
}

// P2SHP2WPKHProofParams contains parameters for P2SH-P2WPKH proof generation
type P2SHP2WPKHProofParams struct {
	SignatureR *big.Int
	SignatureS *big.Int
	PublicKeyX *big.Int
	PublicKeyY *big.Int

	MessageHash     [32]byte
	ScriptHash      [20]byte // Hash160 of the redeem script (P2SH address payload)
	BTCQAddressHash [32]byte
	ChainID         [8]byte
}

// P2SHP2WPKHVerificationParams contains parameters for P2SH-P2WPKH proof verification
type P2SHP2WPKHVerificationParams struct {
	MessageHash     [32]byte
	ScriptHash      [20]byte // Hash160 of the redeem script
	BTCQAddressHash [32]byte
	ChainID         [8]byte
}
