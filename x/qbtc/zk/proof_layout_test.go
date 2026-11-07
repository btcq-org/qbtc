package zk_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"os"
	"testing"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/plonk"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/scs"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ripemd160" //nolint:staticcheck // Bitcoin address hash is defined in terms of RIPEMD160.

	"github.com/btcq-org/qbtc/x/qbtc/zk"
	"github.com/btcq-org/qbtc/x/qbtc/zk/zktest"
)

// Offsets of the two length prefixes in a compressed proof.
const (
	claimedValuesPrefixOffset = 8 * 32
)

func bsb22PrefixOffset(nbCommitments int) int {
	return claimedValuesPrefixOffset + 4 + (6+nbCommitments)*32 + 32 + 32
}

func TestClaimCircuitNbCommitments(t *testing.T) {
	cs, err := frontend.Compile(ecc.BN254.ScalarField(), scs.NewBuilder, zk.NewBTCPubKeyOwnershipCircuitPlaceholder())
	require.NoError(t, err)
	commitments, ok := cs.GetCommitments().(constraint.PlonkCommitments)
	require.True(t, ok)
	require.Len(t, commitments, zk.ClaimCircuitNbCommitments)
}

func TestProofSize(t *testing.T) {
	for n := range 4 {
		require.Len(t, zktest.WellFormedProof(n), zk.ProofSize(n), "nbCommitments=%d", n)
	}
	require.Equal(t, 584, zk.ProofSize(zk.ClaimCircuitNbCommitments))
}

func TestCheckProofLayout(t *testing.T) {
	const n = zk.ClaimCircuitNbCommitments
	valid := zktest.WellFormedProof(n)

	// The well-formed proof also deserializes through gnark.
	p := plonk.NewProof(ecc.BN254)
	_, err := p.ReadFrom(bytes.NewReader(valid))
	require.NoError(t, err)

	setPrefix := func(off int, v uint32) []byte {
		b := bytes.Clone(valid)
		binary.BigEndian.PutUint32(b[off:], v)
		return b
	}
	uncompressed := bytes.Clone(valid)
	uncompressed[0] &^= 0b11 << 6

	tests := []struct {
		name  string
		proof []byte
		nb    int
		err   string
	}{
		{"valid", valid, n, ""},
		{"valid without commitments", zktest.WellFormedProof(0), 0, ""},
		{"empty", nil, n, "proof is 0 bytes"},
		{"truncated", valid[:len(valid)-1], n, "want 584"},
		{"trailing byte", append(bytes.Clone(valid), 0), n, "want 584"},
		{"wrong commitment count for key", valid, 0, "proof is 584 bytes"},
		{"negative commitment count", valid, -1, "invalid commitment count"},
		{"huge Bsb22Commitments prefix", setPrefix(bsb22PrefixOffset(n), 0xFFFFFFFF), n, "Bsb22Commitments count is 4294967295"},
		{"large Bsb22Commitments prefix", setPrefix(bsb22PrefixOffset(n), 1<<26), n, "Bsb22Commitments count is 67108864"},
		{"zero Bsb22Commitments prefix", setPrefix(bsb22PrefixOffset(n), 0), n, "Bsb22Commitments count is 0"},
		{"huge ClaimedValues prefix", setPrefix(claimedValuesPrefixOffset, 0xFFFFFFFF), n, "ClaimedValues count is 4294967295"},
		{"uncompressed point", uncompressed, n, "not a compressed point"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := zk.CheckProofLayout(tc.proof, tc.nb)
			if tc.err == "" {
				require.NoError(t, err)
				return
			}
			require.ErrorContains(t, err, tc.err)
		})
	}
}

// TestVerifyProof_RejectsTamperedLengthPrefix feeds VerifyProof a proof whose
// commitment count prefix would make gnark-crypto allocate about 256 GiB. The
// address check passes, so the proof reaches deserialization; the layout
// check must reject it first.
func TestVerifyProof_RejectsTamperedLengthPrefix(t *testing.T) {
	vkBytes, err := os.ReadFile("testdata/hermez08_64public.vk")
	require.NoError(t, err)
	verifier, err := zk.NewVerifierFromBytes(vkBytes)
	require.NoError(t, err)

	pubKeyHash := sha256.Sum256([]byte("pubkey"))
	h := ripemd160.New()
	h.Write(pubKeyHash[:])
	addr, err := btcutil.NewAddressWitnessPubKeyHash(h.Sum(nil), &chaincfg.MainNetParams)
	require.NoError(t, err)

	// The test key has no commitments, so the prefix is the last 4 bytes.
	proof := zktest.WellFormedProof(0)
	binary.BigEndian.PutUint32(proof[len(proof)-4:], 0xFFFFFFFF)

	err = verifier.VerifyProof(proof, zk.VerificationParams{
		BitcoinAddress:   addr.EncodeAddress(),
		PubKeyHashSHA256: pubKeyHash,
		QBTCAddress:      "qbtc1ddffch4l0ynyd8v4q05j9chzqf7dl2pvz9knds",
		ChainID:          "qbtc-test",
	})
	require.ErrorContains(t, err, "malformed proof")
	require.ErrorContains(t, err, "Bsb22Commitments count is 4294967295")
}
