package zk

import (
	"math/big"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/scs"
	"github.com/consensys/gnark/std/algebra/emulated/sw_emulated"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/test"
	"github.com/stretchr/testify/require"
)

// pubKeyBindingCircuit runs the public-key checks of BTCPubKeyOwnershipCircuit
// and exposes the SEC-compressed encoding they produce.
type pubKeyBindingCircuit struct {
	X          emulated.Element[Secp256k1Fp]
	Y          emulated.Element[Secp256k1Fp]
	Compressed [33]frontend.Variable `gnark:",public"`
}

func (c *pubKeyBindingCircuit) Define(api frontend.API) error {
	field, err := emulated.NewField[Secp256k1Fp](api)
	if err != nil {
		return err
	}
	curve, err := sw_emulated.New[Secp256k1Fp, Secp256k1Fr](api, sw_emulated.GetSecp256k1Params())
	if err != nil {
		return err
	}
	out := compressCheckedPubKey(api, field, curve, &sw_emulated.AffinePoint[Secp256k1Fp]{X: c.X, Y: c.Y})
	for i := range out {
		api.AssertIsEqual(out[i], c.Compressed[i])
	}
	return nil
}

// encodePoint returns the SEC-compressed encoding of (x, y) without reducing x.
func encodePoint(x, y *big.Int) [33]byte {
	var out [33]byte
	out[0] = 0x02 + byte(y.Bit(0))
	x.FillBytes(out[1:])
	return out
}

func pubKeyBindingAssignment(x, y *big.Int, compressed [33]byte) *pubKeyBindingCircuit {
	a := &pubKeyBindingCircuit{
		X: emulated.Element[Secp256k1Fp]{Limbs: bigIntToLimbs(x)},
		Y: emulated.Element[Secp256k1Fp]{Limbs: bigIntToLimbs(y)},
	}
	for i := range compressed {
		a.Compressed[i] = compressed[i]
	}
	return a
}

// smallXPoint returns a secp256k1 point whose x-coordinate is below 2^256 - p,
// so that x + p still fits in 256 bits.
func smallXPoint(t *testing.T) (*big.Int, *big.Int) {
	t.Helper()
	p := btcec.S256().P
	for x := int64(1); x < 1000; x++ {
		bx := big.NewInt(x)
		rhs := new(big.Int).Exp(bx, big.NewInt(3), p)
		rhs.Add(rhs, big.NewInt(7)).Mod(rhs, p)
		if y := new(big.Int).ModSqrt(rhs, p); y != nil {
			return bx, y
		}
	}
	t.Fatal("no small-x point found")
	return nil, nil
}

func TestCompressCheckedPubKey(t *testing.T) {
	field := ecc.BN254.ScalarField()
	p := btcec.S256().P

	key, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	x, y := key.PubKey().X(), key.PubKey().Y()
	var honest [33]byte
	copy(honest[:], key.PubKey().SerializeCompressed())

	t.Run("valid key", func(t *testing.T) {
		require.NoError(t, test.IsSolved(&pubKeyBindingCircuit{}, pubKeyBindingAssignment(x, y, honest), field))
	})

	t.Run("off-curve key is rejected", func(t *testing.T) {
		yOff := new(big.Int).Add(y, big.NewInt(1))
		yOff.Mod(yOff, p)
		require.Error(t, test.IsSolved(&pubKeyBindingCircuit{}, pubKeyBindingAssignment(x, yOff, encodePoint(x, yOff)), field))
	})

	t.Run("point at infinity is rejected", func(t *testing.T) {
		zero := big.NewInt(0)
		require.Error(t, test.IsSolved(&pubKeyBindingCircuit{}, pubKeyBindingAssignment(zero, zero, encodePoint(zero, zero)), field))
	})

	t.Run("non-canonical x encodes canonically", func(t *testing.T) {
		sx, sy := smallXPoint(t)
		xPlusP := new(big.Int).Add(sx, p)
		require.Less(t, xPlusP.BitLen(), 257)
		canonical := encodePoint(sx, sy)
		// x + p is the same point, so it must hash the canonical bytes ...
		require.NoError(t, test.IsSolved(&pubKeyBindingCircuit{}, pubKeyBindingAssignment(xPlusP, sy, canonical), field))
		// ... and never the bytes of x + p.
		require.Error(t, test.IsSolved(&pubKeyBindingCircuit{}, pubKeyBindingAssignment(xPlusP, sy, encodePoint(xPlusP, sy)), field))
	})
}

func TestClaimCircuitPublicInputCount(t *testing.T) {
	if testing.Short() {
		t.Skip("compiling the claim circuit takes a while")
	}
	cs, err := frontend.Compile(ecc.BN254.ScalarField(), scs.NewBuilder, NewBTCPubKeyOwnershipCircuitPlaceholder())
	require.NoError(t, err)
	require.Equal(t, ClaimCircuitNbPublicInputs, cs.GetNbPublicVariables())
}
