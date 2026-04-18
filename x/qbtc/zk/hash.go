package zk

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/hash/ripemd160"
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
