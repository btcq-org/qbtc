package zktest

import (
	"bytes"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark-crypto/ecc/bn254/kzg"
	plonkbn254 "github.com/consensys/gnark/backend/plonk/bn254"
)

// WellFormedProof returns the serialization of a PLONK BN254 proof for a
// circuit with nbCommitments BSB22 commitments, with every point at infinity
// and every scalar zero. It passes zk.CheckProofLayout and deserializes, but
// never verifies.
func WellFormedProof(nbCommitments int) []byte {
	proof := &plonkbn254.Proof{}
	proof.BatchedProof.ClaimedValues = make([]fr.Element, 6+nbCommitments)
	proof.Bsb22Commitments = make([]kzg.Digest, nbCommitments)
	var buf bytes.Buffer
	if _, err := proof.WriteTo(&buf); err != nil {
		panic(err)
	}
	return buf.Bytes()
}
