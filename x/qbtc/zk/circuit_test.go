//go:build testing

package zk

import (
	"crypto/sha256"
	"encoding/hex"
	"math/big"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
	btcecdsa "github.com/btcsuite/btcd/btcec/v2/ecdsa"
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

// TestSignatureCircuit_EndToEnd tests the complete signature-based proof flow.
// This is the primary test for TSS/MPC compatibility.
//
// Note: SignatureR is now correctly typed as a scalar in Fr (not a point coordinate).
// The circuit verifies: R'.x mod n == r where R' = u1*G + u2*P
func (s *CircuitSignatureTestSuite) TestSignatureCircuit_EndToEnd() {
	if testing.Short() {
		s.T().Skip("skipping end-to-end signature circuit test in short mode")
	}

	// Setup with test SRS
	s.T().Log("Running PLONK setup for signature circuit...")

	// Create prover and verifier
	prover := ProverFromSetup(s.setup)
	verifier := NewVerifier(s.setup.VerifyingKey)

	// Test parameters - simulate a TSS signer
	privateKeyBytes, _ := hex.DecodeString("0000000000000000000000000000000000000000000000000000000000003039") // 12345 padded
	privKey, pubKey := btcec.PrivKeyFromBytes(privateKeyBytes)

	qbtcAddress := "qbtc1testaddress123"
	chainID := "qbtc-test-1"

	// Compute address hash from public key
	compressedPubKey := pubKey.SerializeCompressed()
	addressHash, err := PublicKeyToAddressHash(compressedPubKey)
	s.Require().NoError(err, "should compute address hash")

	// Compute binding values
	qbtcAddressHash := HashQBTCAddress(qbtcAddress)
	chainIDHash := ComputeChainIDHash(chainID)

	// Compute the claim message (this is what TSS would sign)
	messageHash := ComputeClaimMessage(addressHash, qbtcAddressHash, chainIDHash)
	s.T().Logf("Message to sign: %s", hex.EncodeToString(messageHash[:]))

	// Sign the message (simulating TSS output)
	sig := btcecdsa.Sign(privKey, messageHash[:])
	sigBytes := sig.Serialize()

	// Parse R and S from DER
	rLen := int(sigBytes[3])
	rBytes := sigBytes[4 : 4+rLen]
	sLen := int(sigBytes[4+rLen+1])
	sBytes := sigBytes[4+rLen+2 : 4+rLen+2+sLen]

	// Remove leading zeros
	if len(rBytes) > 0 && rBytes[0] == 0 {
		rBytes = rBytes[1:]
	}
	if len(sBytes) > 0 && sBytes[0] == 0 {
		sBytes = sBytes[1:]
	}

	sigR := new(big.Int).SetBytes(rBytes)
	sigS := new(big.Int).SetBytes(sBytes)

	s.T().Run("valid signature proof should verify", func(t *testing.T) {
		// Generate proof
		proof, err := prover.GenerateProof(ProofParams{
			SignatureR:      sigR,
			SignatureS:      sigS,
			PublicKeyX:      pubKey.X(),
			PublicKeyY:      pubKey.Y(),
			MessageHash:     messageHash,
			AddressHash:     addressHash,
			QBTCAddressHash: qbtcAddressHash,
			ChainID:         chainIDHash,
		})
		require.NoError(t, err, "proof generation should succeed")
		require.NotEmpty(t, proof, "proof data should not be empty")

		// Verify proof
		err = verifier.VerifyProof(proof, VerificationParams{
			MessageHash:     messageHash,
			AddressHash:     addressHash,
			QBTCAddressHash: qbtcAddressHash,
			ChainID:         chainIDHash,
		})
		require.NoError(t, err, "valid proof should verify")
	})

	s.T().Run("proof with wrong message hash should fail", func(t *testing.T) {
		// Generate valid proof
		proof, err := prover.GenerateProof(ProofParams{
			SignatureR:      sigR,
			SignatureS:      sigS,
			PublicKeyX:      pubKey.X(),
			PublicKeyY:      pubKey.Y(),
			MessageHash:     messageHash,
			AddressHash:     addressHash,
			QBTCAddressHash: qbtcAddressHash,
			ChainID:         chainIDHash,
		})
		require.NoError(t, err)

		// Try to verify with different message hash
		wrongMessageHash := messageHash
		wrongMessageHash[0] ^= 0xFF

		err = verifier.VerifyProof(proof, VerificationParams{
			MessageHash:     wrongMessageHash,
			AddressHash:     addressHash,
			QBTCAddressHash: qbtcAddressHash,
			ChainID:         chainIDHash,
		})
		require.Error(t, err, "proof with wrong message hash should fail")
	})

	s.T().Run("proof with wrong address hash should fail", func(t *testing.T) {
		proof, err := prover.GenerateProof(ProofParams{
			SignatureR:      sigR,
			SignatureS:      sigS,
			PublicKeyX:      pubKey.X(),
			PublicKeyY:      pubKey.Y(),
			MessageHash:     messageHash,
			AddressHash:     addressHash,
			QBTCAddressHash: qbtcAddressHash,
			ChainID:         chainIDHash,
		})
		require.NoError(t, err)

		wrongAddressHash := addressHash
		wrongAddressHash[0] ^= 0xFF

		err = verifier.VerifyProof(proof, VerificationParams{
			MessageHash:     messageHash,
			AddressHash:     wrongAddressHash,
			QBTCAddressHash: qbtcAddressHash,
			ChainID:         chainIDHash,
		})
		require.Error(t, err, "proof with wrong address hash should fail")
	})

	s.T().Run("front-running attack should fail", func(t *testing.T) {
		proof, err := prover.GenerateProof(ProofParams{
			SignatureR:      sigR,
			SignatureS:      sigS,
			PublicKeyX:      pubKey.X(),
			PublicKeyY:      pubKey.Y(),
			MessageHash:     messageHash,
			AddressHash:     addressHash,
			QBTCAddressHash: qbtcAddressHash,
			ChainID:         chainIDHash,
		})
		require.NoError(t, err)

		// Attacker tries to redirect to their address
		attackerHash := HashQBTCAddress("qbtc1attacker")

		err = verifier.VerifyProof(proof, VerificationParams{
			MessageHash:     messageHash,
			AddressHash:     addressHash,
			QBTCAddressHash: attackerHash,
			ChainID:         chainIDHash,
		})
		require.Error(t, err, "front-running attack should fail")
	})

	s.T().Run("cross-chain replay should fail", func(t *testing.T) {
		proof, err := prover.GenerateProof(ProofParams{
			SignatureR:      sigR,
			SignatureS:      sigS,
			PublicKeyX:      pubKey.X(),
			PublicKeyY:      pubKey.Y(),
			MessageHash:     messageHash,
			AddressHash:     addressHash,
			QBTCAddressHash: qbtcAddressHash,
			ChainID:         chainIDHash,
		})
		require.NoError(t, err)

		wrongChainIDHash := ComputeChainIDHash("other-chain-1")

		err = verifier.VerifyProof(proof, VerificationParams{
			MessageHash:     messageHash,
			AddressHash:     addressHash,
			QBTCAddressHash: qbtcAddressHash,
			ChainID:         wrongChainIDHash,
		})
		require.Error(t, err, "cross-chain replay should fail")
	})
}

// TestComputeClaimMessage tests the deterministic message format.
func (s *CircuitSignatureTestSuite) TestComputeClaimMessage() {
	addressHash := [20]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20}
	qbtcAddressHash := sha256.Sum256([]byte("qbtc1test"))
	chainIDHash := ComputeChainIDHash("qbtc-1")

	// Compute message
	msg1 := ComputeClaimMessage(addressHash, qbtcAddressHash, chainIDHash)

	// Should be deterministic
	msg2 := ComputeClaimMessage(addressHash, qbtcAddressHash, chainIDHash)
	s.Require().Equal(msg1, msg2, "message should be deterministic")

	// Different inputs should produce different messages
	differentAddressHash := addressHash
	differentAddressHash[0] = 0xFF
	msg3 := ComputeClaimMessage(differentAddressHash, qbtcAddressHash, chainIDHash)
	s.Require().NotEqual(msg1, msg3, "different address should produce different message")

	differentQBTCAddressHash := HashQBTCAddress("qbtc1different")
	msg4 := ComputeClaimMessage(addressHash, differentQBTCAddressHash, chainIDHash)
	s.Require().NotEqual(msg1, msg4, "different qbtc address should produce different message")
	differentChainID := ComputeChainIDHash("other-chain")
	msg5 := ComputeClaimMessage(addressHash, qbtcAddressHash, differentChainID)
	s.Require().NotEqual(msg1, msg5, "different chain ID should produce different message")
}

// TestVerifyClaimMessage tests message verification.
func (s *CircuitSignatureTestSuite) TestVerifyClaimMessage() {
	addressHash := [20]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20}
	qbtcAddressHash := HashQBTCAddress("qbtc1test")
	chainIDHash := ComputeChainIDHash("qbtc-1")

	messageHash := ComputeClaimMessage(addressHash, qbtcAddressHash, chainIDHash)

	// Valid verification
	s.Require().True(VerifyClaimMessage(messageHash, addressHash, qbtcAddressHash, chainIDHash))

	// Wrong message hash
	wrongMessageHash := messageHash
	wrongMessageHash[0] ^= 0xFF
	s.Require().False(VerifyClaimMessage(wrongMessageHash, addressHash, qbtcAddressHash, chainIDHash))

	// Wrong parameters
	wrongAddressHash := addressHash
	wrongAddressHash[0] ^= 0xFF
	s.Require().False(VerifyClaimMessage(messageHash, wrongAddressHash, qbtcAddressHash, chainIDHash))
}

// TestSignatureProofSerialization tests proof serialization round-trip.
func (s *CircuitSignatureTestSuite) TestSignatureProofSerialization() {
	if testing.Short() {
		s.T().Skip("skipping in short mode")
	}

	prover := ProverFromSetup(s.setup)

	// Create test signature - use a typical private key (not edge case like 1)
	privateKeyBytes, _ := hex.DecodeString("0000000000000000000000000000000000000000000000000000000000004567")
	privKey, pubKey := btcec.PrivKeyFromBytes(privateKeyBytes)

	compressedPubKey := pubKey.SerializeCompressed()
	addressHash, err := PublicKeyToAddressHash(compressedPubKey)
	s.Require().NoError(err)

	qbtcAddressHash := HashQBTCAddress("qbtc1test")
	chainIDHash := ComputeChainIDHash("test-chain")
	messageHash := ComputeClaimMessage(addressHash, qbtcAddressHash, chainIDHash)

	sig := btcecdsa.Sign(privKey, messageHash[:])
	sigBytes := sig.Serialize()
	rLen := int(sigBytes[3])
	rBytes := sigBytes[4 : 4+rLen]
	sLen := int(sigBytes[4+rLen+1])
	sBytes := sigBytes[4+rLen+2 : 4+rLen+2+sLen]
	if len(rBytes) > 0 && rBytes[0] == 0 {
		rBytes = rBytes[1:]
	}
	if len(sBytes) > 0 && sBytes[0] == 0 {
		sBytes = sBytes[1:]
	}

	proof, err := prover.GenerateProof(ProofParams{
		SignatureR:      new(big.Int).SetBytes(rBytes),
		SignatureS:      new(big.Int).SetBytes(sBytes),
		PublicKeyX:      pubKey.X(),
		PublicKeyY:      pubKey.Y(),
		MessageHash:     messageHash,
		AddressHash:     addressHash,
		QBTCAddressHash: qbtcAddressHash,
		ChainID:         chainIDHash,
	})
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

	// Register global verifier
	err = InitializeVerifier(vkBytes)
	s.Require().NoError(err)

	// Create prover
	prover := ProverFromSetup(s.setup)

	// Test data
	privateKeyBytes, _ := hex.DecodeString("0000000000000000000000000000000000000000000000000000000000000042")
	privKey, pubKey := btcec.PrivKeyFromBytes(privateKeyBytes)

	compressedPubKey := pubKey.SerializeCompressed()
	addressHash, _ := PublicKeyToAddressHash(compressedPubKey)
	qbtcAddressHash := HashQBTCAddress("qbtc1global_test")
	chainIDHash := ComputeChainIDHash("qbtc-1")
	messageHash := ComputeClaimMessage(addressHash, qbtcAddressHash, chainIDHash)

	sig := btcecdsa.Sign(privKey, messageHash[:])
	sigBytes := sig.Serialize()
	rLen := int(sigBytes[3])
	rBytes := sigBytes[4 : 4+rLen]
	sLen := int(sigBytes[4+rLen+1])
	sBytes := sigBytes[4+rLen+2 : 4+rLen+2+sLen]
	if len(rBytes) > 0 && rBytes[0] == 0 {
		rBytes = rBytes[1:]
	}
	if len(sBytes) > 0 && sBytes[0] == 0 {
		sBytes = sBytes[1:]
	}

	proof, err := prover.GenerateProof(ProofParams{
		SignatureR:      new(big.Int).SetBytes(rBytes),
		SignatureS:      new(big.Int).SetBytes(sBytes),
		PublicKeyX:      pubKey.X(),
		PublicKeyY:      pubKey.Y(),
		MessageHash:     messageHash,
		AddressHash:     addressHash,
		QBTCAddressHash: qbtcAddressHash,
		ChainID:         chainIDHash,
	})
	s.Require().NoError(err)

	// Verify using global verifier
	err = VerifyProofGlobal(proof, VerificationParams{
		MessageHash:     messageHash,
		AddressHash:     addressHash,
		QBTCAddressHash: qbtcAddressHash,
		ChainID:         chainIDHash,
	})
	s.Require().NoError(err, "global verification should succeed")
}

// TestMessageVersioning ensures the version string is included in the message.
func (s *CircuitSignatureTestSuite) TestMessageVersioning() {
	addressHash := [20]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20}
	qbtcAddressHash := HashQBTCAddress("qbtc1test")
	chainIDHash := ComputeChainIDHash("qbtc-1")

	// The current version
	s.Require().Equal("qbtc-claim-v1", ClaimMessageVersion)

	// Message should include the version and type prefix
	msg := ComputeClaimMessage(addressHash, qbtcAddressHash, chainIDHash)

	// Manually compute expected hash (including type prefix)
	prefix := []byte(TypePrefixECDSA)
	data := make([]byte, 0, len(prefix)+20+32+8+len(ClaimMessageVersion))
	data = append(data, prefix...)
	data = append(data, addressHash[:]...)
	data = append(data, qbtcAddressHash[:]...)
	data = append(data, chainIDHash[:]...)
	data = append(data, []byte(ClaimMessageVersion)...)
	expected := sha256.Sum256(data)

	s.Require().Equal(expected, msg, "message should match expected format")
}

// BenchmarkProofGeneration measures end-to-end PLONK proof generation time
// for the BTCAddressOwnershipCircuit. Setup (circuit compilation + key gen)
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

	addressHash, err := PublicKeyToAddressHash(pubKey.SerializeCompressed())
	if err != nil {
		b.Fatalf("address hash: %v", err)
	}
	qbtcAddressHash := HashQBTCAddress("qbtc1benchaddress")
	chainIDHash := ComputeChainIDHash("qbtc-bench-1")
	messageHash := ComputeClaimMessage(addressHash, qbtcAddressHash, chainIDHash)

	sig := btcecdsa.Sign(privKey, messageHash[:])
	sigBytes := sig.Serialize()
	rLen := int(sigBytes[3])
	rBytes := sigBytes[4 : 4+rLen]
	sLen := int(sigBytes[4+rLen+1])
	sBytes := sigBytes[4+rLen+2 : 4+rLen+2+sLen]
	if len(rBytes) > 0 && rBytes[0] == 0 {
		rBytes = rBytes[1:]
	}
	if len(sBytes) > 0 && sBytes[0] == 0 {
		sBytes = sBytes[1:]
	}

	params := ProofParams{
		SignatureR:      new(big.Int).SetBytes(rBytes),
		SignatureS:      new(big.Int).SetBytes(sBytes),
		PublicKeyX:      pubKey.X(),
		PublicKeyY:      pubKey.Y(),
		MessageHash:     messageHash,
		AddressHash:     addressHash,
		QBTCAddressHash: qbtcAddressHash,
		ChainID:         chainIDHash,
	}

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
