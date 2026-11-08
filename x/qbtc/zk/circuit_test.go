//go:build testing

package zk

import (
	"encoding/hex"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

func TestCircuitSignatureTestSuite(t *testing.T) {
	suite.Run(t, new(CircuitSignatureTestSuite))
}

type CircuitSignatureTestSuite struct {
	suite.Suite
	setup *SetupResult
}

func (s *CircuitSignatureTestSuite) SetupSuite() {
	ClearVerifierForTesting()
	setup, err := SetupWithOptions(TestSetupOptions())
	s.Require().NoError(err)
	s.setup = setup
}

// TestSignatureCircuit_EndToEnd runs the full wallet flow: the user signs the
// claim text with a BIP-137 compact signature, the prover recovers the pubkey
// from it and builds a proof, and the verifier re-derives everything from
// on-chain data.
func (s *CircuitSignatureTestSuite) TestSignatureCircuit_EndToEnd() {
	if testing.Short() {
		s.T().Skip("skipping end-to-end signature circuit test in short mode")
	}

	prover := ProverFromSetup(s.setup)
	verifier := NewVerifier(s.setup.VerifyingKey)

	privateKeyBytes, _ := hex.DecodeString("0000000000000000000000000000000000000000000000000000000000003039") // 12345 padded
	privKey, pubKey := btcec.PrivKeyFromBytes(privateKeyBytes)

	qbtcAddress := "qbtc1testaddress123"
	chainID := "qbtc-test-1"
	bitcoinAddress := p2wpkhAddressForTest(pubKey)

	params, sigBase64, pubKeyHashSHA256 := signClaimForTest(s.T(), privKey, chainID, bitcoinAddress, qbtcAddress)
	s.T().Logf("Message: %q\nSignature: %s", ClaimMessageText(chainID, bitcoinAddress, qbtcAddress, ""), sigBase64)

	proof, err := prover.GenerateProof(params)
	s.Require().NoError(err, "proof generation should succeed")
	s.Require().NotEmpty(proof, "proof data should not be empty")

	valid := VerificationParams{
		ChainID:          chainID,
		BitcoinAddress:   bitcoinAddress,
		QBTCAddress:      qbtcAddress,
		PubKeyHashSHA256: pubKeyHashSHA256,
	}

	s.T().Run("valid signature proof should verify", func(t *testing.T) {
		require.NoError(t, verifier.VerifyProof(proof, valid))
	})

	s.T().Run("same key, other address form of it should fail", func(t *testing.T) {
		// The P2PKH address of the same key hashes to the same Hash160, but the
		// signed text names the P2WPKH address, so the digest differs.
		p := valid
		p.BitcoinAddress = p2pkhAddressForTest(pubKey)
		require.Error(t, verifier.VerifyProof(proof, p))
	})

	s.T().Run("proof with wrong pubkey hash should fail", func(t *testing.T) {
		p := valid
		p.PubKeyHashSHA256[0] ^= 0xFF
		require.ErrorContains(t, verifier.VerifyProof(proof, p), "address hash mismatch")
	})

	s.T().Run("proof for another bitcoin address should fail", func(t *testing.T) {
		other, err := btcec.NewPrivateKey()
		require.NoError(t, err)
		p := valid
		p.BitcoinAddress = p2wpkhAddressForTest(other.PubKey())
		require.Error(t, verifier.VerifyProof(proof, p))
	})

	s.T().Run("front-running attack should fail", func(t *testing.T) {
		p := valid
		p.QBTCAddress = "qbtc1attacker"
		require.Error(t, verifier.VerifyProof(proof, p))
	})

	s.T().Run("cross-chain replay should fail", func(t *testing.T) {
		p := valid
		p.ChainID = "other-chain-1"
		require.Error(t, verifier.VerifyProof(proof, p))
	})

	s.T().Run("invalid bitcoin address string is rejected", func(t *testing.T) {
		p := valid
		p.BitcoinAddress = "not-an-address"
		require.ErrorContains(t, verifier.VerifyProof(proof, p), "invalid Bitcoin address")
	})
}

// TestSignatureProofSerialization checks that a proof can be generated from a
// typical key and is non-empty.
func (s *CircuitSignatureTestSuite) TestSignatureProofSerialization() {
	if testing.Short() {
		s.T().Skip("skipping in short mode")
	}

	prover := ProverFromSetup(s.setup)

	privateKeyBytes, _ := hex.DecodeString("0000000000000000000000000000000000000000000000000000000000004567")
	privKey, pubKey := btcec.PrivKeyFromBytes(privateKeyBytes)

	params, _, _ := signClaimForTest(s.T(), privKey, "test-chain", p2pkhAddressForTest(pubKey), "qbtc1test")
	proof, err := prover.GenerateProof(params)
	s.Require().NoError(err)
	s.Require().NotEmpty(proof)
}

// TestSignatureVerifierGlobalFlow tests the global verifier registration and usage.
func (s *CircuitSignatureTestSuite) TestSignatureVerifierGlobalFlow() {
	if testing.Short() {
		s.T().Skip("skipping in short mode")
	}
	ClearVerifierForTesting()
	vkBytes, err := SerializeVerifyingKey(s.setup.VerifyingKey)
	s.Require().NoError(err)

	err = InitializeVerifier(vkBytes)
	s.Require().NoError(err)

	prover := ProverFromSetup(s.setup)

	privateKeyBytes, _ := hex.DecodeString("0000000000000000000000000000000000000000000000000000000000000042")
	privKey, pubKey := btcec.PrivKeyFromBytes(privateKeyBytes)
	bitcoinAddress := p2wpkhAddressForTest(pubKey)

	params, _, pubKeyHashSHA256 := signClaimForTest(s.T(), privKey, "qbtc-1", bitcoinAddress, "qbtc1global_test")
	proof, err := prover.GenerateProof(params)
	s.Require().NoError(err)

	err = VerifyProofGlobal(proof, VerificationParams{
		ChainID:          "qbtc-1",
		BitcoinAddress:   bitcoinAddress,
		QBTCAddress:      "qbtc1global_test",
		PubKeyHashSHA256: pubKeyHashSHA256,
	})
	s.Require().NoError(err, "global verification should succeed")
}

// BenchmarkProofGeneration measures end-to-end PLONK proof generation time
// for the BTCPubKeyOwnershipCircuit. Setup (circuit compilation + key gen)
// runs once outside the timed loop, so each iteration times only the
// witness-assignment + Prove call that a user would run locally.
//
// Gated behind the `testing` build tag (inherited from this file) so it is
// not compiled into `make bench` (which omits -tags=testing) and is never
// executed by `make test` / `make test-all` / CI (none pass -bench).
// Run explicitly with:
//
//	go test -tags=testing -bench=BenchmarkProofGeneration -run=^$ -benchtime=3x ./x/qbtc/zk/
func BenchmarkProofGeneration(b *testing.B) {
	ClearVerifierForTesting()

	setup, err := SetupWithOptions(TestSetupOptions())
	if err != nil {
		b.Fatalf("setup failed: %v", err)
	}
	prover := ProverFromSetup(setup)

	privateKeyBytes, _ := hex.DecodeString("0000000000000000000000000000000000000000000000000000000000003039")
	privKey, pubKey := btcec.PrivKeyFromBytes(privateKeyBytes)

	// signClaimForTest needs a *testing.T; do the equivalent inline.
	digest := ClaimMessageDigest("qbtc-bench-1", p2wpkhAddressForTest(pubKey), "qbtc1benchaddress", "")
	pub, r, sScalar, err := ParseBIP137Signature(signCompactBase64(privKey, digest), digest)
	if err != nil {
		b.Fatalf("signature: %v", err)
	}
	params := ProofParamsFromSignature(pub, r, sScalar, digest)

	// Warm-up proof so one-time allocations don't skew the first sample,
	// and capture the proof size for reporting.
	proof, err := prover.GenerateProof(params)
	if err != nil {
		b.Fatalf("warm-up proof failed: %v", err)
	}
	proofSize := len(proof)

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		p, err := prover.GenerateProof(params)
		if err != nil {
			b.Fatalf("proof generation failed: %v", err)
		}
		if len(p) == 0 {
			b.Fatal("empty proof")
		}
	}

	b.StopTimer()
	b.ReportMetric(float64(proofSize), "proof_bytes")
	b.ReportMetric(float64(setup.ConstraintSystem.GetNbConstraints()), "constraints")
}
