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

// bits32 stores a 32-bit word as individual bits with bit[0] = LSB.
// Keeping state in this form avoids repeated ToBinary/FromBinary round-trips
// across chained bitwise operations — the dominant constraint overhead in the
// original implementation.
type bits32 [32]frontend.Variable

// bits32FromUint converts a compile-time constant to bits32 with zero circuit constraints.
func bits32FromUint(v uint32) bits32 {
	var b bits32
	for i := range 32 {
		if (v>>i)&1 == 1 {
			b[i] = 1
		} else {
			b[i] = 0
		}
	}
	return b
}

// decompose32 decomposes a field element into bits32 (LSB first). Costs 32 constraints.
func decompose32(api frontend.API, v frontend.Variable) bits32 {
	raw := api.ToBinary(v, 32)
	var b bits32
	copy(b[:], raw)
	return b
}

// recompose32 packs bits32 back into a field element. Zero constraints (linear combination).
func recompose32(api frontend.API, b bits32) frontend.Variable {
	return api.FromBinary(b[:]...)
}

// xor32 bitwise XOR on bits32. Costs 32 multiplication constraints; no ToBinary needed.
func xor32(api frontend.API, a, b bits32) bits32 {
	var r bits32
	for i := range 32 {
		ab := api.Mul(a[i], b[i])
		r[i] = api.Sub(api.Add(a[i], b[i]), api.Mul(2, ab))
	}
	return r
}

// and32 bitwise AND on bits32. Costs 32 multiplication constraints.
func and32(api frontend.API, a, b bits32) bits32 {
	var r bits32
	for i := range 32 {
		r[i] = api.Mul(a[i], b[i])
	}
	return r
}

// or32 bitwise OR on bits32. Costs 32 multiplication constraints.
func or32(api frontend.API, a, b bits32) bits32 {
	var r bits32
	for i := range 32 {
		r[i] = api.Sub(api.Add(a[i], b[i]), api.Mul(a[i], b[i]))
	}
	return r
}

// not32 bitwise NOT on bits32. Zero constraints (all linear).
func not32(api frontend.API, a bits32) bits32 {
	var r bits32
	for i := range 32 {
		r[i] = api.Sub(1, a[i])
	}
	return r
}

// rotateLeft32 left-rotates bits32 by n positions. Zero constraints (bit reordering only).
func rotateLeft32(a bits32, n int) bits32 {
	var r bits32
	for i := range 32 {
		r[i] = a[(i-n+32)%32]
	}
	return r
}

// add32Mod adds two bits32 values modulo 2^32. Costs 33 constraints (ToBinary of the sum).
func add32Mod(api frontend.API, a, b bits32) bits32 {
	sum := api.Add(recompose32(api, a), recompose32(api, b))
	raw := api.ToBinary(sum, 33)
	var r bits32
	copy(r[:], raw[:32])
	return r
}

// ripemdF computes the RIPEMD-160 round function on bits32 values.
// All operands are already decomposed so no ToBinary is needed here.
func ripemdF(api frontend.API, round int, x, y, z bits32) bits32 {
	switch round {
	case 0:
		return xor32(api, xor32(api, x, y), z)
	case 1:
		return or32(api, and32(api, x, y), and32(api, not32(api, x), z))
	case 2:
		return xor32(api, or32(api, x, not32(api, y)), z)
	case 3:
		return or32(api, and32(api, x, z), and32(api, y, not32(api, z)))
	case 4:
		return xor32(api, x, or32(api, y, not32(api, z)))
	default:
		panic("invalid round")
	}
}

// padMessage pads the input message according to RIPEMD-160 spec.
func padMessage(api frontend.API, data []frontend.Variable) []frontend.Variable {
	msgLen := len(data)
	paddedLen := ((msgLen + 9 + 63) / 64) * 64
	padded := make([]frontend.Variable, paddedLen)

	for i := 0; i < msgLen; i++ {
		padded[i] = data[i]
	}
	padded[msgLen] = frontend.Variable(0x80)
	for i := msgLen + 1; i < paddedLen-8; i++ {
		padded[i] = frontend.Variable(0)
	}
	lenBits := uint64(msgLen) * 8
	for i := 0; i < 8; i++ {
		padded[paddedLen-8+i] = frontend.Variable((lenBits >> (i * 8)) & 0xFF)
	}
	return padded
}

// bytesToWord32LE converts 4 bytes to a 32-bit word (little-endian).
func bytesToWord32LE(api frontend.API, bytes []frontend.Variable) frontend.Variable {
	result := bytes[0]
	result = api.Add(result, api.Mul(bytes[1], 256))
	result = api.Add(result, api.Mul(bytes[2], 65536))
	result = api.Add(result, api.Mul(bytes[3], 16777216))
	return result
}

// computeRIPEMD160Circuit computes RIPEMD160 hash in the circuit.
// All working state is maintained as bits32 to eliminate the redundant ToBinary/FromBinary
// calls that occurred when chaining bitwise operations on packed field elements.
func computeRIPEMD160Circuit(api frontend.API, data []frontend.Variable) [20]frontend.Variable {
	padded := padMessage(api, data)

	// IV as constant bits32 — no circuit constraints.
	h := [5]bits32{
		bits32FromUint(ripemd160IV[0]),
		bits32FromUint(ripemd160IV[1]),
		bits32FromUint(ripemd160IV[2]),
		bits32FromUint(ripemd160IV[3]),
		bits32FromUint(ripemd160IV[4]),
	}

	for blockIdx := 0; blockIdx < len(padded)/64; blockIdx++ {
		block := padded[blockIdx*64 : (blockIdx+1)*64]

		// Decompose all 16 message words to bits32 once per block.
		// This avoids re-decomposing x[r] inside each add32Mod call.
		var x [16]bits32
		for i := range 16 {
			x[i] = decompose32(api, bytesToWord32LE(api, block[i*4:(i+1)*4]))
		}

		al, bl, cl, dl, el := h[0], h[1], h[2], h[3], h[4]
		ar, br, cr, dr, er := h[0], h[1], h[2], h[3], h[4]

		// Left line: 80 rounds
		for j := range 80 {
			round := j / 16
			f := ripemdF(api, round, bl, cl, dl)
			k := bits32FromUint(ripemd160KL[round])
			r := ripemd160RL[j]
			s := ripemd160SL[j]

			t := add32Mod(api, al, f)
			t = add32Mod(api, t, x[r])
			t = add32Mod(api, t, k)
			t = rotateLeft32(t, s)
			t = add32Mod(api, t, el)

			al = el
			el = dl
			dl = rotateLeft32(cl, 10)
			cl = bl
			bl = t
		}

		// Right line: 80 rounds
		for j := range 80 {
			round := j / 16
			f := ripemdF(api, 4-round, br, cr, dr)
			k := bits32FromUint(ripemd160KR[round])
			r := ripemd160RR[j]
			s := ripemd160SR[j]

			t := add32Mod(api, ar, f)
			t = add32Mod(api, t, x[r])
			t = add32Mod(api, t, k)
			t = rotateLeft32(t, s)
			t = add32Mod(api, t, er)

			ar = er
			er = dr
			dr = rotateLeft32(cr, 10)
			cr = br
			br = t
		}

		// Final mixing
		t := add32Mod(api, h[1], add32Mod(api, cl, dr))
		h[1] = add32Mod(api, h[2], add32Mod(api, dl, er))
		h[2] = add32Mod(api, h[3], add32Mod(api, el, ar))
		h[3] = add32Mod(api, h[4], add32Mod(api, al, br))
		h[4] = add32Mod(api, h[0], add32Mod(api, bl, cr))
		h[0] = t
	}

	// Serialise hash words to bytes (little-endian).
	// The bits are already decomposed so FromBinary costs zero constraints.
	var result [20]frontend.Variable
	for i, w := range h {
		for j := range 4 {
			result[i*4+j] = api.FromBinary(w[j*8 : (j+1)*8]...)
		}
	}
	return result
}
