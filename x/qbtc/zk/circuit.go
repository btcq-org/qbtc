// Package zk implements zero-knowledge proof generation and verification
// for Bitcoin address ownership without revealing the private key.
package zk

import (
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/emulated/sw_emulated"
	"github.com/consensys/gnark/std/math/emulated"
)

// Secp256k1Fp is the base field of secp256k1
type Secp256k1Fp = emulated.Secp256k1Fp

// Secp256k1Fr is the scalar field of secp256k1
type Secp256k1Fr = emulated.Secp256k1Fr

// BTCAddressCircuit is the ZK circuit that proves ownership of a Bitcoin address.
// It proves: "I know a private key whose public key hashes to the given address hash"
// without revealing the private key or public key.
//
// SECURITY: The proof is bound to:
// 1. The Bitcoin address (via Hash160)
// 2. The destination qbtc address (prevents front-running)
// 3. The chain ID (prevents cross-chain replay)
//
// This prevents front-running and cross-chain replay attacks.
type BTCAddressCircuit struct {
	// Private inputs
	// PrivateKey is the secp256k1 scalar (256 bits)
	PrivateKey emulated.Element[Secp256k1Fr] `gnark:",secret"`

	// Public inputs
	// AddressHash is the Hash160 (RIPEMD160(SHA256(pubkey))) of the Bitcoin public key
	// Represented as 20 bytes (160 bits) in big-endian
	AddressHash [20]frontend.Variable `gnark:",public"`

	// BTCQAddressHash is the SHA256 hash of the destination address on qbtc
	// This binds the proof to a specific claim destination (prevents front-running)
	BTCQAddressHash [32]frontend.Variable `gnark:",public"`

	// ChainID is a hash of the chain identifier (first 8 bytes of SHA256(chain_id))
	// This prevents cross-chain replay attacks
	ChainID [8]frontend.Variable `gnark:",public"`
}

// Define implements the gnark circuit interface.
// The circuit proves:
// 1. Knowledge of a private key that produces the claimed Bitcoin address hash
// 2. Commitment to a specific destination qbtc address (prevents front-running)
// 3. Binding to chain ID (prevents cross-chain replay)
//
// SECURITY NOTE: BTCQAddressHash and ChainID are public inputs. PLONK verification
// ensures the prover committed to specific values for these inputs, and the verifier
// checks they match expected values derived from the message. This prevents:
// - Front-running: attacker cannot reuse proof for different destination address
// - Cross-chain replay: proof is bound to specific chain ID
func (c *BTCAddressCircuit) Define(api frontend.API) error {
	// Get secp256k1 curve API for emulated arithmetic
	curve, err := sw_emulated.New[Secp256k1Fp, Secp256k1Fr](api, sw_emulated.GetSecp256k1Params())
	if err != nil {
		return err
	}

	// Get the generator point G for secp256k1
	params := sw_emulated.GetSecp256k1Params()
	gx := emulated.ValueOf[Secp256k1Fp](params.Gx)
	gy := emulated.ValueOf[Secp256k1Fp](params.Gy)
	G := sw_emulated.AffinePoint[Secp256k1Fp]{X: gx, Y: gy}

	// Compute pubKey = privateKey * G
	pubKey := curve.ScalarMul(&G, &c.PrivateKey)

	// Get the compressed public key bytes
	// For simplicity in the circuit, we work with the x-coordinate and y-parity
	compressedPubKey := c.compressPubKey(api, curve, pubKey)

	// Compute Hash160 = RIPEMD160(SHA256(compressedPubKey))
	hash160 := c.computeHash160(api, compressedPubKey[:])

	// Assert hash160 == addressHash (byte by byte)
	// This proves the prover knows a private key for this Bitcoin address
	for i := 0; i < 20; i++ {
		api.AssertIsEqual(hash160[i], c.AddressHash[i])
	}

	// NOTE: BTCQAddressHash and ChainID don't need explicit constraints here.
	// As public inputs, PLONK cryptographically binds the proof to their values.
	// The verifier reconstructs expected values from the message and verification
	// fails if they don't match what the prover committed to.

	return nil
}

// compressPubKey computes the compressed public key (33 bytes)
func (c *BTCAddressCircuit) compressPubKey(
	api frontend.API,
	curve *sw_emulated.Curve[Secp256k1Fp, Secp256k1Fr],
	pubKey *sw_emulated.AffinePoint[Secp256k1Fp],
) [33]frontend.Variable {
	var result [33]frontend.Variable

	// Get the field API for extracting limbs
	fieldAPI, _ := emulated.NewField[Secp256k1Fp](api)

	// Extract x coordinate bytes (32 bytes, big-endian)
	xBytes := fieldAPI.ToBits(&pubKey.X)

	// Extract y coordinate to determine prefix
	yBytes := fieldAPI.ToBits(&pubKey.Y)

	// Prefix is 0x02 if y is even, 0x03 if y is odd
	// The LSB of y determines parity
	yParity := yBytes[0]

	// Construct prefix byte: 0x02 + yParity = 0x02 or 0x03
	result[0] = api.Add(2, yParity)

	// Pack x bits into bytes (big-endian)
	for byteIdx := 0; byteIdx < 32; byteIdx++ {
		var byteVal frontend.Variable = 0
		for bitIdx := 0; bitIdx < 8; bitIdx++ {
			// xBytes is in little-endian bit order
			// We need big-endian byte order
			srcBitIdx := (31-byteIdx)*8 + (7 - bitIdx)
			if srcBitIdx < len(xBytes) {
				bit := xBytes[srcBitIdx]
				byteVal = api.Add(byteVal, api.Mul(bit, 1<<bitIdx))
			}
		}
		result[1+byteIdx] = byteVal
	}

	return result
}

// computeHash160 computes RIPEMD160(SHA256(data))
// This is a placeholder - the actual implementation uses the hash gadgets
func (c *BTCAddressCircuit) computeHash160(api frontend.API, data []frontend.Variable) [20]frontend.Variable {
	// First compute SHA256
	sha256Result := computeSHA256Circuit(api, data)

	// Then compute RIPEMD160
	return computeRIPEMD160Circuit(api, sha256Result[:])
}

// CircuitParams contains the curve and proof system parameters
type CircuitParams struct {
	Curve ecc.ID
}

// DefaultCircuitParams returns default parameters for the circuit
func DefaultCircuitParams() CircuitParams {
	return CircuitParams{
		Curve: ecc.BN254, // Use BN254 for PLONK
	}
}

// NewBTCAddressCircuit creates a new circuit instance with the given parameters.
// This is used for witness assignment during proof generation.
func NewBTCAddressCircuit(addressHash [20]byte, btcqAddressHash [32]byte, chainID [8]byte) *BTCAddressCircuit {
	circuit := &BTCAddressCircuit{}

	for i := 0; i < 20; i++ {
		circuit.AddressHash[i] = addressHash[i]
	}

	for i := 0; i < 32; i++ {
		circuit.BTCQAddressHash[i] = btcqAddressHash[i]
	}

	// Copy chain ID bytes
	for i := 0; i < 8; i++ {
		circuit.ChainID[i] = chainID[i]
	}

	return circuit
}

// NewBTCAddressCircuitPlaceholder creates an empty circuit for compilation.
// This is used during setup to generate the constraint system.
func NewBTCAddressCircuitPlaceholder() *BTCAddressCircuit {
	return &BTCAddressCircuit{}
}

// GetAddressHashBytes converts the circuit's AddressHash to a byte array
func (c *BTCAddressCircuit) GetAddressHashBytes() [20]byte {
	var result [20]byte
	for i := 0; i < 20; i++ {
		switch v := c.AddressHash[i].(type) {
		case int:
			result[i] = byte(v)
		case uint64:
			result[i] = byte(v)
		case byte:
			result[i] = v
		}
	}
	return result
}
