package zk

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/hash/sha2"
	"github.com/consensys/gnark/std/math/uints"
)

// computeSHA256Circuit computes SHA256 hash in the circuit
func computeSHA256Circuit(api frontend.API, data []frontend.Variable) [32]frontend.Variable {
	// Convert frontend.Variable slice to uints.U8 slice
	uintAPI, err := uints.New[uints.U32](api)
	if err != nil {
		panic(err)
	}

	// Convert input data to U8 array
	input := make([]uints.U8, len(data))
	for i, v := range data {
		input[i] = uintAPI.ByteValueOf(v)
	}

	// Create SHA256 hasher
	hasher, err := sha2.New(api)
	if err != nil {
		panic(err)
	}

	// Write input data
	hasher.Write(input)

	// Get the hash result
	hashResult := hasher.Sum()

	// Convert back to frontend.Variable array
	var result [32]frontend.Variable
	for i := 0; i < 32; i++ {
		result[i] = hashResult[i].Val
	}

	return result
}

// computeRIPEMD160Circuit computes RIPEMD160 hash in the circuit
// Note: gnark doesn't have native RIPEMD160 support, so we implement it
// using circuit constraints. This is a simplified version that uses lookup tables.
func computeRIPEMD160Circuit(api frontend.API, data []frontend.Variable) [20]frontend.Variable {
	// RIPEMD160 implementation in ZK circuits is complex.
	// For a production system, you would implement the full RIPEMD160 algorithm
	// using circuit constraints (around 640 rounds of operations).
	//
	// For this implementation, we use a MiMC-based hash as a placeholder
	// that provides the same security properties in the ZK context.
	// In production, you would replace this with actual RIPEMD160 circuit.

	return computeRIPEMD160Native(api, data)
}

// computeRIPEMD160Native implements RIPEMD160 using native circuit operations
// This is a faithful implementation of RIPEMD160 in circuit form
func computeRIPEMD160Native(api frontend.API, data []frontend.Variable) [20]frontend.Variable {
	// Pad the message according to RIPEMD160 spec
	paddedData := padRIPEMD160(api, data)

	// Initialize hash values
	h0 := frontend.Variable(0x67452301)
	h1 := frontend.Variable(0xEFCDAB89)
	h2 := frontend.Variable(0x98BADCFE)
	h3 := frontend.Variable(0x10325476)
	h4 := frontend.Variable(0xC3D2E1F0)

	// Process each 512-bit block
	for blockStart := 0; blockStart < len(paddedData); blockStart += 64 {
		block := paddedData[blockStart : blockStart+64]

		// Process this block
		a, b, c, d, e := processRIPEMD160Block(api, block, h0, h1, h2, h3, h4)

		// Update hash values
		h0, h1, h2, h3, h4 = a, b, c, d, e
	}

	// Convert final hash to bytes
	return hashToBytes(api, h0, h1, h2, h3, h4)
}

// padRIPEMD160 pads the input according to RIPEMD160 specification
func padRIPEMD160(api frontend.API, data []frontend.Variable) []frontend.Variable {
	msgLen := len(data)
	// Add 1 bit (0x80 byte) + padding zeros + 8 bytes length
	// Total length must be multiple of 64 bytes

	// Calculate padded length
	paddedLen := ((msgLen + 9 + 63) / 64) * 64
	padded := make([]frontend.Variable, paddedLen)

	// Copy original data
	copy(padded, data)

	// Add 0x80 byte
	padded[msgLen] = frontend.Variable(0x80)

	// Fill with zeros (already zero-initialized in Go)
	for i := msgLen + 1; i < paddedLen-8; i++ {
		padded[i] = frontend.Variable(0)
	}

	// Add length in bits (little-endian, 64-bit)
	lenBits := msgLen * 8
	for i := 0; i < 8; i++ {
		padded[paddedLen-8+i] = frontend.Variable((lenBits >> (i * 8)) & 0xFF)
	}

	return padded
}

// processRIPEMD160Block processes a single 512-bit block
func processRIPEMD160Block(api frontend.API, block []frontend.Variable,
	h0, h1, h2, h3, h4 frontend.Variable) (frontend.Variable, frontend.Variable, frontend.Variable, frontend.Variable, frontend.Variable) {

	// Convert block bytes to 16 32-bit words (little-endian)
	var x [16]frontend.Variable
	for i := 0; i < 16; i++ {
		x[i] = api.Add(
			block[i*4],
			api.Mul(block[i*4+1], 256),
			api.Mul(block[i*4+2], 65536),
			api.Mul(block[i*4+3], 16777216),
		)
	}

	// Left round
	al, bl, cl, dl, el := h0, h1, h2, h3, h4

	// Right round
	ar, br, cr, dr, er := h0, h1, h2, h3, h4

	// RIPEMD160 round constants and functions
	// Left rounds
	for j := 0; j < 80; j++ {
		var f, k frontend.Variable
		var r, s int

		switch {
		case j < 16:
			f = xorVar(api, xorVar(api, bl, cl), dl)
			k = frontend.Variable(0x00000000)
			r = rhoL[j]
			s = piL[j]
		case j < 32:
			f = orVar(api, andVar(api, bl, cl), andVar(api, notVar(api, bl), dl))
			k = frontend.Variable(0x5A827999)
			r = rhoL[j]
			s = piL[j]
		case j < 48:
			f = xorVar(api, orVar(api, bl, notVar(api, cl)), dl)
			k = frontend.Variable(0x6ED9EBA1)
			r = rhoL[j]
			s = piL[j]
		case j < 64:
			f = orVar(api, andVar(api, bl, dl), andVar(api, cl, notVar(api, dl)))
			k = frontend.Variable(0x8F1BBCDC)
			r = rhoL[j]
			s = piL[j]
		default:
			f = xorVar(api, bl, orVar(api, cl, notVar(api, dl)))
			k = frontend.Variable(0xA953FD4E)
			r = rhoL[j]
			s = piL[j]
		}

		t := add32(api, al, f)
		t = add32(api, t, x[r])
		t = add32(api, t, k)
		t = rotl32(api, t, s)
		t = add32(api, t, el)

		al = el
		el = dl
		dl = rotl32(api, cl, 10)
		cl = bl
		bl = t
	}

	// Right rounds (similar structure with different constants)
	for j := 0; j < 80; j++ {
		var f, k frontend.Variable
		var r, s int

		switch {
		case j < 16:
			f = xorVar(api, br, orVar(api, cr, notVar(api, dr)))
			k = frontend.Variable(0x50A28BE6)
			r = rhoR[j]
			s = piR[j]
		case j < 32:
			f = orVar(api, andVar(api, br, dr), andVar(api, cr, notVar(api, dr)))
			k = frontend.Variable(0x5C4DD124)
			r = rhoR[j]
			s = piR[j]
		case j < 48:
			f = xorVar(api, orVar(api, br, notVar(api, cr)), dr)
			k = frontend.Variable(0x6D703EF3)
			r = rhoR[j]
			s = piR[j]
		case j < 64:
			f = orVar(api, andVar(api, br, cr), andVar(api, notVar(api, br), dr))
			k = frontend.Variable(0x7A6D76E9)
			r = rhoR[j]
			s = piR[j]
		default:
			f = xorVar(api, xorVar(api, br, cr), dr)
			k = frontend.Variable(0x00000000)
			r = rhoR[j]
			s = piR[j]
		}

		t := add32(api, ar, f)
		t = add32(api, t, x[r])
		t = add32(api, t, k)
		t = rotl32(api, t, s)
		t = add32(api, t, er)

		ar = er
		er = dr
		dr = rotl32(api, cr, 10)
		cr = br
		br = t
	}

	// Final addition
	t := add32(api, h1, add32(api, cl, dr))
	newH1 := add32(api, h2, add32(api, dl, er))
	newH2 := add32(api, h3, add32(api, el, ar))
	newH3 := add32(api, h4, add32(api, al, br))
	newH4 := add32(api, h0, add32(api, bl, cr))
	newH0 := t

	return newH0, newH1, newH2, newH3, newH4
}

// hashToBytes converts 5 32-bit words to 20 bytes (little-endian)
func hashToBytes(api frontend.API, h0, h1, h2, h3, h4 frontend.Variable) [20]frontend.Variable {
	var result [20]frontend.Variable

	words := []frontend.Variable{h0, h1, h2, h3, h4}
	for i, w := range words {
		for j := 0; j < 4; j++ {
			// Extract byte j from word w (little-endian)
			result[i*4+j] = extractByte(api, w, j)
		}
	}

	return result
}

// Helper functions for 32-bit arithmetic in circuits

// add32 performs 32-bit addition with wrap-around
// In a ZK circuit, we handle the modular reduction by bit decomposition
func add32(api frontend.API, a, b frontend.Variable) frontend.Variable {
	sum := api.Add(a, b)
	// Decompose to 33 bits to capture overflow, then take lower 32
	bits := api.ToBinary(sum, 33)
	return api.FromBinary(bits[:32]...)
}

// rotl32 performs 32-bit left rotation
func rotl32(api frontend.API, x frontend.Variable, n int) frontend.Variable {
	// Decompose to 32 bits
	bits := api.ToBinary(x, 32)

	// Rotate the bits
	rotated := make([]frontend.Variable, 32)
	for i := 0; i < 32; i++ {
		srcIdx := (i - n + 32) % 32
		rotated[i] = bits[srcIdx]
	}

	return api.FromBinary(rotated...)
}

// xorVar performs XOR of two 32-bit values
func xorVar(api frontend.API, a, b frontend.Variable) frontend.Variable {
	// XOR can be computed as (a + b - 2*AND(a,b))
	// But for 32-bit values, we use bit decomposition
	aBits := api.ToBinary(a, 32)
	bBits := api.ToBinary(b, 32)

	resultBits := make([]frontend.Variable, 32)
	for i := 0; i < 32; i++ {
		// XOR: a + b - 2*a*b
		resultBits[i] = api.Sub(api.Add(aBits[i], bBits[i]), api.Mul(2, api.Mul(aBits[i], bBits[i])))
	}

	return api.FromBinary(resultBits...)
}

// andVar performs AND of two 32-bit values
func andVar(api frontend.API, a, b frontend.Variable) frontend.Variable {
	aBits := api.ToBinary(a, 32)
	bBits := api.ToBinary(b, 32)

	resultBits := make([]frontend.Variable, 32)
	for i := 0; i < 32; i++ {
		resultBits[i] = api.Mul(aBits[i], bBits[i])
	}

	return api.FromBinary(resultBits...)
}

// orVar performs OR of two 32-bit values
func orVar(api frontend.API, a, b frontend.Variable) frontend.Variable {
	aBits := api.ToBinary(a, 32)
	bBits := api.ToBinary(b, 32)

	resultBits := make([]frontend.Variable, 32)
	for i := 0; i < 32; i++ {
		// OR: a + b - a*b
		resultBits[i] = api.Sub(api.Add(aBits[i], bBits[i]), api.Mul(aBits[i], bBits[i]))
	}

	return api.FromBinary(resultBits...)
}

// notVar performs NOT of a 32-bit value
func notVar(api frontend.API, a frontend.Variable) frontend.Variable {
	aBits := api.ToBinary(a, 32)

	resultBits := make([]frontend.Variable, 32)
	for i := 0; i < 32; i++ {
		// NOT: 1 - a
		resultBits[i] = api.Sub(1, aBits[i])
	}

	return api.FromBinary(resultBits...)
}

// extractByte extracts byte n from a 32-bit word (little-endian)
func extractByte(api frontend.API, word frontend.Variable, n int) frontend.Variable {
	bits := api.ToBinary(word, 32)

	// Extract 8 bits for byte n
	byteBits := bits[n*8 : (n+1)*8]

	return api.FromBinary(byteBits...)
}

// RIPEMD160 constants
var rhoL = []int{
	0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
	7, 4, 13, 1, 10, 6, 15, 3, 12, 0, 9, 5, 2, 14, 11, 8,
	3, 10, 14, 4, 9, 15, 8, 1, 2, 7, 0, 6, 13, 11, 5, 12,
	1, 9, 11, 10, 0, 8, 12, 4, 13, 3, 7, 15, 14, 5, 6, 2,
	4, 0, 5, 9, 7, 12, 2, 10, 14, 1, 3, 8, 11, 6, 15, 13,
}

var piL = []int{
	11, 14, 15, 12, 5, 8, 7, 9, 11, 13, 14, 15, 6, 7, 9, 8,
	7, 6, 8, 13, 11, 9, 7, 15, 7, 12, 15, 9, 11, 7, 13, 12,
	11, 13, 6, 7, 14, 9, 13, 15, 14, 8, 13, 6, 5, 12, 7, 5,
	11, 12, 14, 15, 14, 15, 9, 8, 9, 14, 5, 6, 8, 6, 5, 12,
	9, 15, 5, 11, 6, 8, 13, 12, 5, 12, 13, 14, 11, 8, 5, 6,
}

var rhoR = []int{
	5, 14, 7, 0, 9, 2, 11, 4, 13, 6, 15, 8, 1, 10, 3, 12,
	6, 11, 3, 7, 0, 13, 5, 10, 14, 15, 8, 12, 4, 9, 1, 2,
	15, 5, 1, 3, 7, 14, 6, 9, 11, 8, 12, 2, 10, 0, 4, 13,
	8, 6, 4, 1, 3, 11, 15, 0, 5, 12, 2, 13, 9, 7, 10, 14,
	12, 15, 10, 4, 1, 5, 8, 7, 6, 2, 13, 14, 0, 3, 9, 11,
}

var piR = []int{
	8, 9, 9, 11, 13, 15, 15, 5, 7, 7, 8, 11, 14, 14, 12, 6,
	9, 13, 15, 7, 12, 8, 9, 11, 7, 7, 12, 7, 6, 15, 13, 11,
	9, 7, 15, 11, 8, 6, 6, 14, 12, 13, 5, 14, 13, 13, 7, 5,
	15, 5, 8, 11, 14, 14, 6, 14, 6, 9, 12, 9, 12, 5, 15, 8,
	8, 5, 12, 9, 12, 5, 14, 6, 8, 13, 6, 5, 15, 13, 11, 11,
}
