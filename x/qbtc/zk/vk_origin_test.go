package zk

import (
	"bytes"
	"math/big"
	"os"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark/backend/plonk"
	plonkbn254 "github.com/consensys/gnark/backend/plonk/bn254"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/scs"
	"github.com/consensys/gnark/test/unsafekzg"
	"github.com/stretchr/testify/require"
)

const (
	// hermezTestPTAUPath is the official powersOfTau28_hez_final_08.ptau.
	hermezTestPTAUPath = "testdata/powersOfTau28_hez_final_08.ptau"
	// hermezTestPTAUBlake2b is its hash from https://github.com/iden3/snarkjs#7-prepare-phase-2.
	hermezTestPTAUBlake2b = "d6a8fb3a04feb600096c3b791f936a578c4e664d262e4aa24beed1b7a9a96aa5eb72864d628db247e9293384b74b36ffb52ca8d148d6e1b8b51e279fdf57b583"
	// hermezTestVKPath is the verifying key that srsFromPTAU and plonk.Setup
	// produce from hermezTestPTAUPath for sixtyFourPublicCircuit.
	// TestSrsFromPTAU regenerates it and checks it is byte-identical.
	hermezTestVKPath = "testdata/hermez08_64public.vk"
)

type sixtyFourPublicCircuit struct {
	In  [ClaimCircuitNbPublicInputs]frontend.Variable `gnark:",public"`
	Sec frontend.Variable
}

func (c *sixtyFourPublicCircuit) Define(api frontend.API) error {
	api.AssertIsEqual(api.Add(c.In[0], c.Sec), c.In[1])
	return nil
}

func loadHermezTestVK(t *testing.T) plonk.VerifyingKey {
	t.Helper()
	bz, err := os.ReadFile(hermezTestVKPath)
	require.NoError(t, err)
	vk, err := DeserializeVerifyingKey(bz)
	require.NoError(t, err)
	return vk
}

// setupFromHermezTestPTAU runs the production SRS path on the small Hermez PTAU.
func setupFromHermezTestPTAU(t *testing.T) plonk.VerifyingKey {
	t.Helper()
	require.NoError(t, verifyFileBlake2b(hermezTestPTAUPath, hermezTestPTAUBlake2b))
	f, err := os.Open(hermezTestPTAUPath)
	require.NoError(t, err)
	defer f.Close()
	cs, err := frontend.Compile(ecc.BN254.ScalarField(), scs.NewBuilder, &sixtyFourPublicCircuit{})
	require.NoError(t, err)
	srs, srsLagrange, err := srsFromPTAU(f, cs.GetNbConstraints()+cs.GetNbPublicVariables())
	require.NoError(t, err)
	_, vk, err := plonk.Setup(cs, srs, srsLagrange)
	require.NoError(t, err)
	return vk
}

// ptau.ToSRS leaves the KZG pairing lines at zero; the setup path must fill
// them in, or the verifying key's pairing check accepts any input.
func TestSrsFromPTAU(t *testing.T) {
	vk := setupFromHermezTestPTAU(t)
	key := vk.(*plonkbn254.VerifyingKey)
	for i := range key.Kzg.G2 {
		require.Equal(t, bn254.PrecomputeLines(key.Kzg.G2[i]), key.Kzg.Lines[i])
	}
	require.NoError(t, ValidateClaimVerifyingKey(vk))

	bz, err := SerializeVerifyingKey(vk)
	require.NoError(t, err)
	committed, err := os.ReadFile(hermezTestVKPath)
	require.NoError(t, err)
	require.True(t, bytes.Equal(committed, bz), "testdata verifying key differs from a fresh setup")
}

// With zero lines the KZG pairing check holds for any input.
func TestPairingCheckWithZeroLinesAcceptsAnything(t *testing.T) {
	_, _, g1, g2 := bn254.Generators()
	var p, q bn254.G1Affine
	p.ScalarMultiplication(&g1, big.NewInt(5))
	q.ScalarMultiplication(&g1, big.NewInt(11))

	var zero [2][2][len(bn254.LoopCounter)]bn254.LineEvaluationAff
	ok, err := bn254.PairingCheckFixedQ([]bn254.G1Affine{p, q}, zero[:])
	require.NoError(t, err)
	require.True(t, ok)

	var tauG2 bn254.G2Affine
	tauG2.ScalarMultiplication(&g2, big.NewInt(7))
	lines := [2][2][len(bn254.LoopCounter)]bn254.LineEvaluationAff{bn254.PrecomputeLines(g2), bn254.PrecomputeLines(tauG2)}
	ok, err = bn254.PairingCheckFixedQ([]bn254.G1Affine{p, q}, lines[:])
	require.NoError(t, err)
	require.False(t, ok)
}

func TestNewVerifierRecomputesLines(t *testing.T) {
	vk := loadHermezTestVK(t)
	key := vk.(*plonkbn254.VerifyingKey)
	want := key.Kzg.Lines
	key.Kzg.Lines = [2][2][len(bn254.LoopCounter)]bn254.LineEvaluationAff{}
	NewVerifier(vk)
	require.Equal(t, want, key.Kzg.Lines)
}

func TestValidateClaimVerifyingKey(t *testing.T) {
	t.Run("hermez setup is accepted", func(t *testing.T) {
		require.NoError(t, ValidateClaimVerifyingKey(loadHermezTestVK(t)))
	})

	t.Run("test SRS is rejected", func(t *testing.T) {
		cs, err := frontend.Compile(ecc.BN254.ScalarField(), scs.NewBuilder, &sixtyFourPublicCircuit{})
		require.NoError(t, err)
		srs, srsLagrange, err := unsafekzg.NewSRS(cs)
		require.NoError(t, err)
		_, vk, err := plonk.Setup(cs, srs, srsLagrange)
		require.NoError(t, err)
		err = ValidateClaimVerifyingKey(vk)
		require.ErrorContains(t, err, "[τ]G2")
	})

	t.Run("zero lines are rejected", func(t *testing.T) {
		vk := loadHermezTestVK(t)
		vk.(*plonkbn254.VerifyingKey).Kzg.Lines = [2][2][len(bn254.LoopCounter)]bn254.LineEvaluationAff{}
		require.ErrorContains(t, ValidateClaimVerifyingKey(vk), "precomputed lines")
	})

	t.Run("lines for another tau are rejected", func(t *testing.T) {
		vk := loadHermezTestVK(t)
		key := vk.(*plonkbn254.VerifyingKey)
		// lines precomputed from a different G2 point, Hermez G2 bytes untouched
		var other bn254.G2Affine
		other.Double(&key.Kzg.G2[1])
		key.Kzg.Lines[1] = bn254.PrecomputeLines(other)
		require.ErrorContains(t, ValidateClaimVerifyingKey(vk), "precomputed lines")
	})

	t.Run("wrong number of public inputs is rejected", func(t *testing.T) {
		vk := loadHermezTestVK(t)
		vk.(*plonkbn254.VerifyingKey).NbPublicVariables = ClaimCircuitNbPublicInputs + 1
		require.ErrorContains(t, ValidateClaimVerifyingKey(vk), "public inputs")
	})
}
