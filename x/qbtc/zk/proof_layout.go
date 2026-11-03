package zk

import (
	"encoding/binary"
	"fmt"

	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
)

// ClaimCircuitNbCommitments is the number of BSB22 commitments in
// BTCPubKeyOwnershipCircuit. The emulated secp256k1 arithmetic uses gnark's
// range checker, which adds one commitment. TestClaimCircuitNbCommitments
// compiles the circuit and checks this value.
const ClaimCircuitNbCommitments = 1

const (
	proofPointSize  = bn254.SizeOfG1AffineCompressed
	proofScalarSize = fr.Bytes
	proofPrefixSize = 4

	// proofPointFlagMask selects the two metadata bits of a serialized point.
	// Both bits clear marks an uncompressed point.
	proofPointFlagMask = 0b11 << 6
)

// ProofSize returns the byte length of a compressed PLONK BN254 proof for a
// circuit with nbCommitments BSB22 commitments.
//
// The encoding, written by plonk.Proof.WriteTo, is:
//
//	8 points: LRO[0..2], Z, H[0..2], BatchedProof.H
//	uint32 count, then count scalars: BatchedProof.ClaimedValues (6 + nbCommitments)
//	1 point:  ZShiftedOpening.H
//	1 scalar: ZShiftedOpening.ClaimedValue
//	uint32 count, then count points: Bsb22Commitments (nbCommitments)
func ProofSize(nbCommitments int) int {
	nbPoints := 9 + nbCommitments
	nbScalars := 6 + nbCommitments + 1
	return nbPoints*proofPointSize + nbScalars*proofScalarSize + 2*proofPrefixSize
}

// CheckProofLayout rejects proof unless it has the exact compressed layout of
// a PLONK BN254 proof with nbCommitments BSB22 commitments.
//
// gnark-crypto decodes a point slice by allocating its uint32 length prefix
// before reading any point, so a tampered prefix makes plonk.Proof.ReadFrom
// allocate up to hundreds of GiB and abort the process. Every untrusted proof
// must pass this check before it is deserialized. A total length check alone
// is not enough, because a correctly sized payload can still carry a large
// prefix.
//
// Uncompressed points are rejected; the prover always writes compressed ones.
// Point and scalar values are left to ReadFrom and the PLONK verifier.
func CheckProofLayout(proof []byte, nbCommitments int) error {
	if nbCommitments < 0 {
		return fmt.Errorf("invalid commitment count %d", nbCommitments)
	}
	if want := ProofSize(nbCommitments); len(proof) != want {
		return fmt.Errorf("proof is %d bytes, want %d", len(proof), want)
	}

	off := 0
	points := func(field string, n int) error {
		for i := range n {
			if proof[off]&proofPointFlagMask == 0 {
				return fmt.Errorf("proof %s[%d] is not a compressed point", field, i)
			}
			off += proofPointSize
		}
		return nil
	}
	prefix := func(field string, want int) error {
		got := binary.BigEndian.Uint32(proof[off:])
		off += proofPrefixSize
		if uint64(got) != uint64(want) {
			return fmt.Errorf("proof %s count is %d, want %d", field, got, want)
		}
		return nil
	}

	if err := points("LRO/Z/H/BatchedProof.H", 8); err != nil {
		return err
	}
	if err := prefix("BatchedProof.ClaimedValues", 6+nbCommitments); err != nil {
		return err
	}
	off += (6 + nbCommitments) * proofScalarSize
	if err := points("ZShiftedOpening.H", 1); err != nil {
		return err
	}
	off += proofScalarSize
	if err := prefix("Bsb22Commitments", nbCommitments); err != nil {
		return err
	}
	return points("Bsb22Commitments", nbCommitments)
}
