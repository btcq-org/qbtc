package zk

import (
	"os"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/plonk"
	plonkbn254 "github.com/consensys/gnark/backend/plonk/bn254"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/scs"
	"github.com/consensys/gnark/test/unsafekzg"
	"github.com/stretchr/testify/require"
)

// hermezTestVKPath is a verifying key set up from powersOfTau28_hez_final_08.ptau
// (Blake2b d6a8fb3a…57b583) for a circuit with ClaimCircuitNbPublicInputs public
// inputs and one constraint, In[0] + Sec == In[1].
const hermezTestVKPath = "testdata/hermez08_64public.vk"

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

	t.Run("wrong number of public inputs is rejected", func(t *testing.T) {
		vk := loadHermezTestVK(t)
		vk.(*plonkbn254.VerifyingKey).NbPublicVariables = ClaimCircuitNbPublicInputs + 1
		require.ErrorContains(t, ValidateClaimVerifyingKey(vk), "public inputs")
	})
}
