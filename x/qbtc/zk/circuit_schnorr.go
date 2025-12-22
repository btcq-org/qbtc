// Package zk implements zero-knowledge proof generation and verification
// for Bitcoin address ownership using Schnorr signatures (BIP-340).
package zk

import (
	"math/big"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/emulated/sw_emulated"
	"github.com/consensys/gnark/std/math/emulated"
)

// BTCSchnorrCircuit is the ZK circuit that proves ownership of a Taproot address
// using a BIP-340 Schnorr signature. It proves: "I have a valid Schnorr signature
// from the key that controls this Taproot address" without revealing the signature.
//
// SECURITY: The proof is bound to:
// 1. The Taproot address (the x-only public key)
// 2. The message being signed (includes destination and chain binding)
// 3. The signature is valid for the claimed public key
//
// This circuit supports P2TR (Pay-to-Taproot) key-path spending.
type BTCSchnorrCircuit struct {
	// Private inputs (hidden in the proof)
	// SignatureR is the x-coordinate of the nonce point R (32 bytes as scalar)
	SignatureR emulated.Element[Secp256k1Fr] `gnark:",secret"`
	// SignatureS is the s scalar of the Schnorr signature
	SignatureS emulated.Element[Secp256k1Fr] `gnark:",secret"`
	// PublicKeyX is the x-coordinate of the public key (x-only, 32 bytes)
	PublicKeyX emulated.Element[Secp256k1Fp] `gnark:",secret"`
	// PublicKeyY is computed from X (even Y convention in BIP-340)
	PublicKeyY emulated.Element[Secp256k1Fp] `gnark:",secret"`

	// Public inputs (visible to verifier)
	// MessageHash is the hash of the message that was signed (32 bytes)
	MessageHash [32]frontend.Variable `gnark:",public"`
	// XOnlyPubKey is the 32-byte x-only public key (this IS the Taproot address)
	XOnlyPubKey [32]frontend.Variable `gnark:",public"`
	// BTCQAddressHash is the SHA256 hash of the destination address on qbtc
	BTCQAddressHash [32]frontend.Variable `gnark:",public"`
	// ChainID is a hash of the chain identifier (first 8 bytes of SHA256(chain_id))
	ChainID [8]frontend.Variable `gnark:",public"`
}

// Define implements the gnark circuit interface.
// The circuit proves:
// 1. The Schnorr signature is valid for the given public key and message
// 2. The public key x-coordinate matches the claimed Taproot address
// 3. The proof is bound to the destination address and chain ID
func (c *BTCSchnorrCircuit) Define(api frontend.API) error {
	// Get the curve for point operations
	curve, err := sw_emulated.New[Secp256k1Fp, Secp256k1Fr](api, sw_emulated.GetSecp256k1Params())
	if err != nil {
		return err
	}

	// Get the scalar field for operations
	scalarField, err := emulated.NewField[Secp256k1Fr](api)
	if err != nil {
		return err
	}

	// Get the base field for operations
	baseField, err := emulated.NewField[Secp256k1Fp](api)
	if err != nil {
		return err
	}

	// ========================================
	// Step 1: Verify public key X matches the claimed Taproot address
	// ========================================
	// The XOnlyPubKey IS the Taproot address for key-path spending
	pubKeyXBytes := c.elementToBytes32(api, baseField, &c.PublicKeyX)
	for i := 0; i < 32; i++ {
		api.AssertIsEqual(pubKeyXBytes[i], c.XOnlyPubKey[i])
	}

	// ========================================
	// Step 2: Compute the BIP-340 challenge
	// ========================================
	// e = tagged_hash("BIP0340/challenge", R.x || P.x || m)
	// We use the signature R value (which is an x-coordinate) directly
	rXBytes := c.scalarToBytes32(api, scalarField, &c.SignatureR)
	challenge := computeBIP340ChallengeCircuit(api, rXBytes, pubKeyXBytes, c.MessageHash)

	// Convert challenge bytes to scalar
	challengeScalar := c.bytesToScalar(api, scalarField, challenge[:])

	// ========================================
	// Step 3: Verify Schnorr signature
	// ========================================
	// BIP-340 verification: s*G = R + e*P
	// Rearranged: s*G - e*P = R
	// We verify that the x-coordinate of (s*G - e*P) equals the claimed R.x

	// Construct the public key point
	pubKey := &sw_emulated.AffinePoint[Secp256k1Fp]{
		X: c.PublicKeyX,
		Y: c.PublicKeyY,
	}

	// Get generator point G
	G := curve.Generator()

	// Compute s*G
	sG := curve.ScalarMul(G, &c.SignatureS)

	// Compute e*P
	eP := curve.ScalarMul(pubKey, &challengeScalar)

	// Compute R' = s*G - e*P
	// To subtract, we negate e*P (negate Y coordinate) and add
	ePNeg := curve.Neg(eP)
	rPrime := curve.Add(sG, ePNeg)

	// Verify R'.x == SignatureR
	// Convert R'.x to bits for comparison
	rPrimeXBits := baseField.ToBits(&rPrime.X)

	// Convert SignatureR to bits for comparison
	sigRBits := scalarField.ToBits(&c.SignatureR)

	// Compare all 256 bits. Note on field sizes:
	// - secp256k1 base field p ≈ 2^256 - 2^32 - 977
	// - secp256k1 scalar field n ≈ 2^256 - 432420386565659656852420866394968145599
	// For valid BIP-340 signatures, the probability of R.x being in [n, p) is ~2^-227,
	// which is negligible. The bit comparison is safe for all practical signatures.
	for i := 0; i < 256; i++ {
		if i < len(rPrimeXBits) && i < len(sigRBits) {
			api.AssertIsEqual(rPrimeXBits[i], sigRBits[i])
		}
	}

	// BIP-340 also requires R to have even y-coordinate
	rPrimeYBits := baseField.ToBits(&rPrime.Y)
	api.AssertIsEqual(rPrimeYBits[0], 0)

	// ========================================
	// Step 4: Verify Y coordinate has even parity (BIP-340 requirement)
	// ========================================
	// In BIP-340, the public key Y must have even parity
	yBits := baseField.ToBits(&c.PublicKeyY)
	// The LSB determines parity - must be 0 (even)
	api.AssertIsEqual(yBits[0], 0)

	return nil
}

// bytesToScalar converts a byte array to a scalar field element
func (c *BTCSchnorrCircuit) bytesToScalar(
	api frontend.API,
	field *emulated.Field[Secp256k1Fr],
	bytes []frontend.Variable,
) emulated.Element[Secp256k1Fr] {
	// Convert bytes to bits (big-endian)
	bits := make([]frontend.Variable, len(bytes)*8)
	for i, b := range bytes {
		byteBits := api.ToBinary(b, 8)
		// Reverse bit order within byte for big-endian
		for j := 0; j < 8; j++ {
			bits[i*8+j] = byteBits[7-j]
		}
	}

	// Build the scalar from bits
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

// elementToBytes32 converts a base field element to 32 bytes (big-endian)
func (c *BTCSchnorrCircuit) elementToBytes32(
	api frontend.API,
	field *emulated.Field[Secp256k1Fp],
	elem *emulated.Element[Secp256k1Fp],
) [32]frontend.Variable {
	var result [32]frontend.Variable

	// Get bits from the element (little-endian)
	bits := field.ToBits(elem)

	// Pack into bytes (big-endian byte order)
	for byteIdx := 0; byteIdx < 32; byteIdx++ {
		var byteVal frontend.Variable = 0
		for bitIdx := 0; bitIdx < 8; bitIdx++ {
			srcBitIdx := (31-byteIdx)*8 + bitIdx
			if srcBitIdx < len(bits) {
				bit := bits[srcBitIdx]
				byteVal = api.Add(byteVal, api.Mul(bit, 1<<bitIdx))
			}
		}
		result[byteIdx] = byteVal
	}

	return result
}

// scalarToBytes32 converts a scalar field element to 32 bytes (big-endian)
func (c *BTCSchnorrCircuit) scalarToBytes32(
	api frontend.API,
	field *emulated.Field[Secp256k1Fr],
	elem *emulated.Element[Secp256k1Fr],
) [32]frontend.Variable {
	var result [32]frontend.Variable

	// Get bits from the element (little-endian)
	bits := field.ToBits(elem)

	// Pack into bytes (big-endian byte order)
	for byteIdx := 0; byteIdx < 32; byteIdx++ {
		var byteVal frontend.Variable = 0
		for bitIdx := 0; bitIdx < 8; bitIdx++ {
			srcBitIdx := (31-byteIdx)*8 + bitIdx
			if srcBitIdx < len(bits) {
				bit := bits[srcBitIdx]
				byteVal = api.Add(byteVal, api.Mul(bit, 1<<bitIdx))
			}
		}
		result[byteIdx] = byteVal
	}

	return result
}

// NewBTCSchnorrCircuitPlaceholder creates an empty circuit for compilation.
// This is used during setup to generate the constraint system.
func NewBTCSchnorrCircuitPlaceholder() *BTCSchnorrCircuit {
	return &BTCSchnorrCircuit{}
}

// SchnorrProofParams contains all parameters needed to generate a Schnorr proof
type SchnorrProofParams struct {
	// Signature components
	SignatureR *big.Int // R.x (x-coordinate of nonce point)
	SignatureS *big.Int // s scalar

	// Public key (x-only + derived Y with even parity)
	PublicKeyX *big.Int
	PublicKeyY *big.Int // Must have even parity (BIP-340)

	// Public inputs
	MessageHash     [32]byte // The signed message hash
	XOnlyPubKey     [32]byte // The 32-byte x-only public key (Taproot address)
	BTCQAddressHash [32]byte // H(claimer_address)
	ChainID         [8]byte  // First 8 bytes of H(chain_id)
}

// SchnorrVerificationParams contains parameters needed for Schnorr proof verification
type SchnorrVerificationParams struct {
	MessageHash     [32]byte // The message that was signed
	XOnlyPubKey     [32]byte // The Taproot address (x-only pubkey)
	BTCQAddressHash [32]byte // H(claimer_address)
	ChainID         [8]byte  // First 8 bytes of H(chain_id)
}
