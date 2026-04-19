package zk

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/hash/ripemd160"
	"github.com/consensys/gnark/std/hash/sha2"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/std/math/uints"
)

// bytesToScalar converts 32 big-endian bytes to a Secp256k1Fr scalar element using
// 4×64-bit limbs. Avoids api.ToBinary per byte — range is enforced by the verifier.
func bytesToScalar(api frontend.API, bytes []frontend.Variable) emulated.Element[Secp256k1Fr] {
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


// computeRIPEMD160Circuit computes RIPEMD160 hash in the circuit using gnark's standard library.
// Uses uints.U32 with PLONK lookup tables internally — more efficient than multiplication-based ops.
func computeRIPEMD160Circuit(api frontend.API, data []frontend.Variable) [20]frontend.Variable {
	uintAPI, err := uints.New[uints.U32](api)
	if err != nil {
		panic(err)
	}

	input := make([]uints.U8, len(data))
	for i, v := range data {
		input[i] = uintAPI.ByteValueOf(v)
	}

	hasher, err := ripemd160.New(api)
	if err != nil {
		panic(err)
	}
	hasher.Write(input)
	out := hasher.Sum()

	var result [20]frontend.Variable
	for i, b := range out {
		result[i] = b.Val
	}
	return result
}
