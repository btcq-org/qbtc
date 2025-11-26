package zk

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/hash/sha2"
	"github.com/consensys/gnark/std/math/uints"
)

// computeSHA256Circuit computes SHA256 hash in the circuit using gnark's standard library
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

	// Create SHA256 hasher using gnark's standard implementation
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

// RIPEMD160 Constants
// Initial hash values (IV)
var ripemd160IV = [5]uint32{
	0x67452301,
	0xEFCDAB89,
	0x98BADCFE,
	0x10325476,
	0xC3D2E1F0,
}

// Left line: message word selection
var ripemd160RL = [80]int{
	0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
	7, 4, 13, 1, 10, 6, 15, 3, 12, 0, 9, 5, 2, 14, 11, 8,
	3, 10, 14, 4, 9, 15, 8, 1, 2, 7, 0, 6, 13, 11, 5, 12,
	1, 9, 11, 10, 0, 8, 12, 4, 13, 3, 7, 15, 14, 5, 6, 2,
	4, 0, 5, 9, 7, 12, 2, 10, 14, 1, 3, 8, 11, 6, 15, 13,
}

// Right line: message word selection
var ripemd160RR = [80]int{
	5, 14, 7, 0, 9, 2, 11, 4, 13, 6, 15, 8, 1, 10, 3, 12,
	6, 11, 3, 7, 0, 13, 5, 10, 14, 15, 8, 12, 4, 9, 1, 2,
	15, 5, 1, 3, 7, 14, 6, 9, 11, 8, 12, 2, 10, 0, 4, 13,
	8, 6, 4, 1, 3, 11, 15, 0, 5, 12, 2, 13, 9, 7, 10, 14,
	12, 15, 10, 4, 1, 5, 8, 7, 6, 2, 13, 14, 0, 3, 9, 11,
}

// Left line: rotation amounts
var ripemd160SL = [80]int{
	11, 14, 15, 12, 5, 8, 7, 9, 11, 13, 14, 15, 6, 7, 9, 8,
	7, 6, 8, 13, 11, 9, 7, 15, 7, 12, 15, 9, 11, 7, 13, 12,
	11, 13, 6, 7, 14, 9, 13, 15, 14, 8, 13, 6, 5, 12, 7, 5,
	11, 12, 14, 15, 14, 15, 9, 8, 9, 14, 5, 6, 8, 6, 5, 12,
	9, 15, 5, 11, 6, 8, 13, 12, 5, 12, 13, 14, 11, 8, 5, 6,
}

// Right line: rotation amounts
var ripemd160SR = [80]int{
	8, 9, 9, 11, 13, 15, 15, 5, 7, 7, 8, 11, 14, 14, 12, 6,
	9, 13, 15, 7, 12, 8, 9, 11, 7, 7, 12, 7, 6, 15, 13, 11,
	9, 7, 15, 11, 8, 6, 6, 14, 12, 13, 5, 14, 13, 13, 7, 5,
	15, 5, 8, 11, 14, 14, 6, 14, 6, 9, 12, 9, 12, 5, 15, 8,
	8, 5, 12, 9, 12, 5, 14, 6, 8, 13, 6, 5, 15, 13, 11, 11,
}

// Left line: round constants
var ripemd160KL = [5]uint32{
	0x00000000,
	0x5A827999,
	0x6ED9EBA1,
	0x8F1BBCDC,
	0xA953FD4E,
}

// Right line: round constants
var ripemd160KR = [5]uint32{
	0x50A28BE6,
	0x5C4DD124,
	0x6D703EF3,
	0x7A6D76E9,
	0x00000000,
}

// computeRIPEMD160Circuit computes RIPEMD160 hash in the circuit
// This implementation follows the RIPEMD-160 specification exactly
func computeRIPEMD160Circuit(api frontend.API, data []frontend.Variable) [20]frontend.Variable {
	// Pad the message
	padded := padMessage(api, data)

	// Initialize hash state with IV
	h0 := frontend.Variable(ripemd160IV[0])
	h1 := frontend.Variable(ripemd160IV[1])
	h2 := frontend.Variable(ripemd160IV[2])
	h3 := frontend.Variable(ripemd160IV[3])
	h4 := frontend.Variable(ripemd160IV[4])

	// Process each 64-byte block
	for blockIdx := 0; blockIdx < len(padded)/64; blockIdx++ {
		block := padded[blockIdx*64 : (blockIdx+1)*64]

		// Parse block into 16 32-bit words (little-endian)
		var x [16]frontend.Variable
		for i := 0; i < 16; i++ {
			x[i] = bytesToWord32LE(api, block[i*4:(i+1)*4])
		}

		// Initialize working variables
		al, bl, cl, dl, el := h0, h1, h2, h3, h4
		ar, br, cr, dr, er := h0, h1, h2, h3, h4

		// 80 rounds for left line
		for j := 0; j < 80; j++ {
			round := j / 16
			f := ripemdF(api, round, bl, cl, dl)
			k := frontend.Variable(ripemd160KL[round])
			r := ripemd160RL[j]
			s := ripemd160SL[j]

			t := add32Mod(api, al, f)
			t = add32Mod(api, t, x[r])
			t = add32Mod(api, t, k)
			t = rotateLeft32(api, t, s)
			t = add32Mod(api, t, el)

			al = el
			el = dl
			dl = rotateLeft32(api, cl, 10)
			cl = bl
			bl = t
		}

		// 80 rounds for right line
		for j := 0; j < 80; j++ {
			round := j / 16
			f := ripemdF(api, 4-round, br, cr, dr) // Note: reversed round order for right line
			k := frontend.Variable(ripemd160KR[round])
			r := ripemd160RR[j]
			s := ripemd160SR[j]

			t := add32Mod(api, ar, f)
			t = add32Mod(api, t, x[r])
			t = add32Mod(api, t, k)
			t = rotateLeft32(api, t, s)
			t = add32Mod(api, t, er)

			ar = er
			er = dr
			dr = rotateLeft32(api, cr, 10)
			cr = br
			br = t
		}

		// Final addition
		t := add32Mod(api, h1, add32Mod(api, cl, dr))
		h1 = add32Mod(api, h2, add32Mod(api, dl, er))
		h2 = add32Mod(api, h3, add32Mod(api, el, ar))
		h3 = add32Mod(api, h4, add32Mod(api, al, br))
		h4 = add32Mod(api, h0, add32Mod(api, bl, cr))
		h0 = t
	}

	// Convert hash words to bytes (little-endian)
	return wordsToBytes20LE(api, h0, h1, h2, h3, h4)
}

// ripemdF computes the round function f for RIPEMD-160
func ripemdF(api frontend.API, round int, x, y, z frontend.Variable) frontend.Variable {
	switch round {
	case 0:
		// f(x, y, z) = x XOR y XOR z
		return xor32(api, xor32(api, x, y), z)
	case 1:
		// f(x, y, z) = (x AND y) OR (NOT x AND z)
		return or32(api, and32(api, x, y), and32(api, not32(api, x), z))
	case 2:
		// f(x, y, z) = (x OR NOT y) XOR z
		return xor32(api, or32(api, x, not32(api, y)), z)
	case 3:
		// f(x, y, z) = (x AND z) OR (y AND NOT z)
		return or32(api, and32(api, x, z), and32(api, y, not32(api, z)))
	case 4:
		// f(x, y, z) = x XOR (y OR NOT z)
		return xor32(api, x, or32(api, y, not32(api, z)))
	default:
		panic("invalid round")
	}
}

// padMessage pads the input message according to RIPEMD-160 spec
func padMessage(api frontend.API, data []frontend.Variable) []frontend.Variable {
	msgLen := len(data)
	// Padding: add 1 bit (0x80), then zeros, then 64-bit length
	// Total length must be multiple of 64 bytes

	// Calculate padded length
	paddedLen := ((msgLen + 9 + 63) / 64) * 64
	padded := make([]frontend.Variable, paddedLen)

	// Copy original data
	for i := 0; i < msgLen; i++ {
		padded[i] = data[i]
	}

	// Add 0x80 byte
	padded[msgLen] = frontend.Variable(0x80)

	// Fill with zeros (already zero in Go)
	for i := msgLen + 1; i < paddedLen-8; i++ {
		padded[i] = frontend.Variable(0)
	}

	// Add length in bits as 64-bit little-endian
	lenBits := uint64(msgLen) * 8
	for i := 0; i < 8; i++ {
		padded[paddedLen-8+i] = frontend.Variable((lenBits >> (i * 8)) & 0xFF)
	}

	return padded
}

// bytesToWord32LE converts 4 bytes to a 32-bit word (little-endian)
func bytesToWord32LE(api frontend.API, bytes []frontend.Variable) frontend.Variable {
	result := bytes[0]
	result = api.Add(result, api.Mul(bytes[1], 256))
	result = api.Add(result, api.Mul(bytes[2], 65536))
	result = api.Add(result, api.Mul(bytes[3], 16777216))
	return result
}

// wordsToBytes20LE converts 5 32-bit words to 20 bytes (little-endian)
func wordsToBytes20LE(api frontend.API, h0, h1, h2, h3, h4 frontend.Variable) [20]frontend.Variable {
	var result [20]frontend.Variable
	words := []frontend.Variable{h0, h1, h2, h3, h4}
	for i, w := range words {
		for j := 0; j < 4; j++ {
			result[i*4+j] = extractByte32(api, w, j)
		}
	}
	return result
}

// add32Mod performs 32-bit addition with modular wrap
func add32Mod(api frontend.API, a, b frontend.Variable) frontend.Variable {
	sum := api.Add(a, b)
	// Take modulo 2^32
	bits := api.ToBinary(sum, 33)
	return api.FromBinary(bits[:32]...)
}

// rotateLeft32 performs 32-bit left rotation
func rotateLeft32(api frontend.API, x frontend.Variable, n int) frontend.Variable {
	bits := api.ToBinary(x, 32)
	rotated := make([]frontend.Variable, 32)
	for i := 0; i < 32; i++ {
		srcIdx := (i - n + 32) % 32
		rotated[i] = bits[srcIdx]
	}
	return api.FromBinary(rotated...)
}

// xor32 performs bitwise XOR on 32-bit values
func xor32(api frontend.API, a, b frontend.Variable) frontend.Variable {
	aBits := api.ToBinary(a, 32)
	bBits := api.ToBinary(b, 32)
	resultBits := make([]frontend.Variable, 32)
	for i := 0; i < 32; i++ {
		// XOR: a + b - 2*a*b (works for bits 0,1)
		ab := api.Mul(aBits[i], bBits[i])
		resultBits[i] = api.Sub(api.Add(aBits[i], bBits[i]), api.Mul(2, ab))
	}
	return api.FromBinary(resultBits...)
}

// and32 performs bitwise AND on 32-bit values
func and32(api frontend.API, a, b frontend.Variable) frontend.Variable {
	aBits := api.ToBinary(a, 32)
	bBits := api.ToBinary(b, 32)
	resultBits := make([]frontend.Variable, 32)
	for i := 0; i < 32; i++ {
		resultBits[i] = api.Mul(aBits[i], bBits[i])
	}
	return api.FromBinary(resultBits...)
}

// or32 performs bitwise OR on 32-bit values
func or32(api frontend.API, a, b frontend.Variable) frontend.Variable {
	aBits := api.ToBinary(a, 32)
	bBits := api.ToBinary(b, 32)
	resultBits := make([]frontend.Variable, 32)
	for i := 0; i < 32; i++ {
		// OR: a + b - a*b (works for bits 0,1)
		resultBits[i] = api.Sub(api.Add(aBits[i], bBits[i]), api.Mul(aBits[i], bBits[i]))
	}
	return api.FromBinary(resultBits...)
}

// not32 performs bitwise NOT on a 32-bit value
func not32(api frontend.API, a frontend.Variable) frontend.Variable {
	aBits := api.ToBinary(a, 32)
	resultBits := make([]frontend.Variable, 32)
	for i := 0; i < 32; i++ {
		resultBits[i] = api.Sub(1, aBits[i])
	}
	return api.FromBinary(resultBits...)
}

// extractByte32 extracts byte n from a 32-bit word (little-endian)
func extractByte32(api frontend.API, word frontend.Variable, n int) frontend.Variable {
	bits := api.ToBinary(word, 32)
	byteBits := bits[n*8 : (n+1)*8]
	return api.FromBinary(byteBits...)
}
