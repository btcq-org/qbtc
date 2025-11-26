package zk

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ripemd160"
)

// TestCircuit is a simple circuit for testing hash functions
type TestRIPEMD160Circuit struct {
	Input    [33]frontend.Variable `gnark:",public"` // 33 bytes (compressed pubkey)
	Expected [20]frontend.Variable `gnark:",public"` // 20 bytes (RIPEMD160 output)
}

func (c *TestRIPEMD160Circuit) Define(api frontend.API) error {
	// Compute RIPEMD160 of the input
	result := computeRIPEMD160Circuit(api, c.Input[:])

	// Assert equality
	for i := 0; i < 20; i++ {
		api.AssertIsEqual(result[i], c.Expected[i])
	}

	return nil
}

// TestHash160Circuit tests the full Hash160 (RIPEMD160(SHA256(x)))
type TestHash160Circuit struct {
	Input    [33]frontend.Variable `gnark:",public"` // 33 bytes (compressed pubkey)
	Expected [20]frontend.Variable `gnark:",public"` // 20 bytes (Hash160 output)
}

func (c *TestHash160Circuit) Define(api frontend.API) error {
	// First SHA256
	sha256Result := computeSHA256Circuit(api, c.Input[:])

	// Then RIPEMD160
	result := computeRIPEMD160Circuit(api, sha256Result[:])

	// Assert equality
	for i := 0; i < 20; i++ {
		api.AssertIsEqual(result[i], c.Expected[i])
	}

	return nil
}

// computeHash160 computes RIPEMD160(SHA256(data)) using standard Go libraries
func computeHash160(data []byte) []byte {
	sha := sha256.Sum256(data)
	ripemd := ripemd160.New()
	ripemd.Write(sha[:])
	return ripemd.Sum(nil)
}

// computeRIPEMD160 computes RIPEMD160 using standard Go library
func computeRIPEMD160(data []byte) []byte {
	hasher := ripemd160.New()
	hasher.Write(data)
	return hasher.Sum(nil)
}

func TestRIPEMD160Circuit_KnownVectors(t *testing.T) {
	// Test vectors from RIPEMD-160 specification
	testCases := []struct {
		name     string
		input    []byte
		expected string
	}{
		{
			name:     "empty",
			input:    []byte{},
			expected: "9c1185a5c5e9fc54612808977ee8f548b2258d31",
		},
		{
			name:     "a",
			input:    []byte("a"),
			expected: "0bdc9d2d256b3ee9daae347be6f4dc835a467ffe",
		},
		{
			name:     "abc",
			input:    []byte("abc"),
			expected: "8eb208f7e05d987a9b044a8e98c6b087f15a0bfc",
		},
		{
			name:     "message digest",
			input:    []byte("message digest"),
			expected: "5d0689ef49d2fae572b881b123a85ffa21595f36",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Verify using standard library
			result := computeRIPEMD160(tc.input)
			resultHex := hex.EncodeToString(result)
			require.Equal(t, tc.expected, resultHex, "Standard library result mismatch")
		})
	}
}

func TestHash160_StandardLibrary(t *testing.T) {
	// Test with known compressed public key
	// This is the compressed pubkey for private key = 1
	compressedPubKey, _ := hex.DecodeString("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")

	hash160 := computeHash160(compressedPubKey)
	t.Logf("Hash160 of pubkey for privkey=1: %s", hex.EncodeToString(hash160))

	require.Len(t, hash160, 20)
}

// TestRIPEMD160CircuitCorrectness verifies the circuit produces correct results
func TestRIPEMD160CircuitCorrectness(t *testing.T) {
	// Skip in short mode as circuit compilation is slow
	if testing.Short() {
		t.Skip("skipping circuit test in short mode")
	}

	// Use a 33-byte input (like a compressed public key)
	input := make([]byte, 33)
	for i := range input {
		input[i] = byte(i)
	}

	// Compute expected result using standard library
	expected := computeRIPEMD160(input)

	// Create circuit assignment
	var circuit TestRIPEMD160Circuit
	for i := 0; i < 33; i++ {
		circuit.Input[i] = input[i]
	}
	for i := 0; i < 20; i++ {
		circuit.Expected[i] = expected[i]
	}

	// Test the circuit
	err := test.IsSolved(&TestRIPEMD160Circuit{}, &circuit, ecc.BN254.ScalarField())
	require.NoError(t, err, "RIPEMD160 circuit should produce correct output")
}

// TestHash160CircuitCorrectness verifies the full Hash160 circuit
func TestHash160CircuitCorrectness(t *testing.T) {
	// Skip in short mode as circuit compilation is slow
	if testing.Short() {
		t.Skip("skipping circuit test in short mode")
	}

	// Use a 33-byte input (compressed public key)
	input := make([]byte, 33)
	input[0] = 0x02 // Even y
	for i := 1; i < 33; i++ {
		input[i] = byte(i)
	}

	// Compute expected result using standard library
	expected := computeHash160(input)

	// Create circuit assignment
	var circuit TestHash160Circuit
	for i := 0; i < 33; i++ {
		circuit.Input[i] = input[i]
	}
	for i := 0; i < 20; i++ {
		circuit.Expected[i] = expected[i]
	}

	// Test the circuit
	err := test.IsSolved(&TestHash160Circuit{}, &circuit, ecc.BN254.ScalarField())
	require.NoError(t, err, "Hash160 circuit should produce correct output")
}

// TestHash160CircuitWithRealPubkey tests with a real Bitcoin public key
func TestHash160CircuitWithRealPubkey(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping circuit test in short mode")
	}

	// Compressed public key for private key = 1
	compressedPubKey, _ := hex.DecodeString("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")

	// Compute expected Hash160
	expected := computeHash160(compressedPubKey)
	t.Logf("Expected Hash160: %s", hex.EncodeToString(expected))

	// Create circuit assignment
	var circuit TestHash160Circuit
	for i := 0; i < 33; i++ {
		circuit.Input[i] = compressedPubKey[i]
	}
	for i := 0; i < 20; i++ {
		circuit.Expected[i] = expected[i]
	}

	// Test the circuit
	err := test.IsSolved(&TestHash160Circuit{}, &circuit, ecc.BN254.ScalarField())
	require.NoError(t, err, "Hash160 circuit should work with real pubkey")
}

// TestRIPEMD160CircuitProof generates and verifies an actual proof
func TestRIPEMD160CircuitProof(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping proof test in short mode")
	}

	// Use a 33-byte input
	input := make([]byte, 33)
	for i := range input {
		input[i] = byte(i * 7)
	}

	expected := computeRIPEMD160(input)

	// Create witness
	var witness TestRIPEMD160Circuit
	for i := 0; i < 33; i++ {
		witness.Input[i] = input[i]
	}
	for i := 0; i < 20; i++ {
		witness.Expected[i] = expected[i]
	}

	// Full test including proof generation
	assert := test.NewAssert(t)
	assert.ProverSucceeded(&TestRIPEMD160Circuit{}, &witness, test.WithCurves(ecc.BN254), test.WithBackends(backend.PLONK))
}


