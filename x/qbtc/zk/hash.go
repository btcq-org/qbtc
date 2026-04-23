package zk

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/emulated/sw_emulated"
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

// compressPubKeyFromPoint returns the 33-byte SEC-compressed encoding of a
// secp256k1 point: prefix byte (0x02 for even Y, 0x03 for odd Y) followed by
// big-endian X. We decompose X and Y into bits via field.ToBits and repack X
// into bytes; the bit-decomposition relation ties the bytes to pubKey.X
// implicitly, so no extra equality check is needed.
//
// A hint-based variant (producing bytes off-circuit and then asserting
// equality against pubKey.X) was benchmarked and came out ~1,200 constraints
// more expensive: the AssertIsEqual + packLimbs range-checks + ToBitsCanonical
// on Y together cost more than the single ToBits(X) they save. ToBits-based
// compression is the cheaper construction for this circuit shape.
func compressPubKeyFromPoint(
	api frontend.API,
	field *emulated.Field[Secp256k1Fp],
	pubKey *sw_emulated.AffinePoint[Secp256k1Fp],
) [33]frontend.Variable {
	var result [33]frontend.Variable
	// field.ToBits returns bits in little-endian order: bit[0] is LSB.
	xBits := field.ToBits(&pubKey.X)
	yBits := field.ToBits(&pubKey.Y)
	yParity := yBits[0]
	result[0] = api.Add(2, yParity)
	for byteIdx := 0; byteIdx < 32; byteIdx++ {
		var byteVal frontend.Variable = 0
		for bitIdx := 0; bitIdx < 8; bitIdx++ {
			srcBitIdx := (31-byteIdx)*8 + bitIdx
			if srcBitIdx < len(xBits) {
				byteVal = api.Add(byteVal, api.Mul(xBits[srcBitIdx], 1<<bitIdx))
			}
		}
		result[1+byteIdx] = byteVal
	}
	return result
}

// computeSHA256Circuit computes SHA256 hash in the circuit using gnark's standard library.
func computeSHA256Circuit(api frontend.API, data []frontend.Variable) [32]frontend.Variable {
	uintAPI, err := uints.New[uints.U32](api)
	if err != nil {
		panic(err)
	}

	input := make([]uints.U8, len(data))
	for i, v := range data {
		input[i] = uintAPI.ByteValueOf(v)
	}

	hasher, err := sha2.New(api)
	if err != nil {
		panic(err)
	}
	hasher.Write(input)
	hashResult := hasher.Sum()

	var result [32]frontend.Variable
	for i := 0; i < 32; i++ {
		result[i] = hashResult[i].Val
	}
	return result
}
