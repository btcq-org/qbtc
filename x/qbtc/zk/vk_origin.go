package zk

import (
	"encoding/hex"
	"fmt"

	"github.com/consensys/gnark/backend/plonk"
	plonkbn254 "github.com/consensys/gnark/backend/plonk/bn254"
)

// ClaimCircuitNbPublicInputs is the number of public inputs of
// BTCPubKeyOwnershipCircuit: 32 MessageHash bytes plus 32 PubKeyHashSHA256 bytes.
const ClaimCircuitNbPublicInputs = 64

// KZG verifying key points of the Hermez Powers of Tau ceremony, in gnark's
// compressed encoding. Every powersOfTau28_hez_final_NN.ptau file shares them;
// they were read from the _08 and _12 files (Blake2b hashes checked against
// https://github.com/iden3/snarkjs#7-prepare-phase-2), and the verifying key of
// the first qbtc chain carries the same points.
const (
	hermezKzgG1    = "8000000000000000000000000000000000000000000000000000000000000001"
	hermezKzgG2    = "998e9393920d483a7260bfb731fb5d25f1aa493335a9e71297e485b7aef312c21800deef121f1e76426a00665e5c4479674322d4f75edadd46debd5cd992f6ed"
	hermezKzgTauG2 = "e6186a2d65ee4d2f9c9a5b91f86597d35f192cd120caf7e935d8443d1938e23d30441fd1b5d3370482c42152a8899027716989a6996c2535bc9f7fee8aaef79e"
)

// ValidateClaimVerifyingKey checks that vk comes from a PLONK setup over the
// Hermez Powers of Tau and has the claim circuit's number of public inputs.
// A key built from the unsafe test SRS (TestSetupOptions) fails, because its
// [τ]G2 point differs.
//
// This does not prove that vk belongs to BTCPubKeyOwnershipCircuit; compare the
// key's hash with the published setup output for that.
func ValidateClaimVerifyingKey(vk plonk.VerifyingKey) error {
	key, ok := vk.(*plonkbn254.VerifyingKey)
	if !ok {
		return fmt.Errorf("verifying key is %T, want a BN254 PLONK key", vk)
	}
	if key.NbPublicVariables != ClaimCircuitNbPublicInputs {
		return fmt.Errorf("verifying key has %d public inputs, want %d", key.NbPublicVariables, ClaimCircuitNbPublicInputs)
	}
	g1 := key.Kzg.G1.Bytes()
	g2 := key.Kzg.G2[0].Bytes()
	tauG2 := key.Kzg.G2[1].Bytes()
	if hex.EncodeToString(g1[:]) != hermezKzgG1 || hex.EncodeToString(g2[:]) != hermezKzgG2 {
		return fmt.Errorf("verifying key KZG generators do not match the Hermez Powers of Tau")
	}
	if hex.EncodeToString(tauG2[:]) != hermezKzgTauG2 {
		return fmt.Errorf("verifying key [τ]G2 does not match the Hermez Powers of Tau; it was not set up from the production SRS")
	}
	return nil
}
