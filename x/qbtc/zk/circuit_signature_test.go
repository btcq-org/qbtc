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
)

// TestSignatureCircuit_EndToEnd tests the complete signature-based proof flow.
// This is the primary test for TSS/MPC compatibility.
//
// Note: SignatureR is now correctly typed as a scalar in Fr (not a point coordinate).
// The circuit verifies: R'.x mod n == r where R' = u1*G + u2*P
func TestSignatureCircuit_EndToEnd(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping end-to-end signature circuit test in short mode")
	}

	// Setup with test SRS
	t.Log("Running PLONK setup for signature circuit...")
	setup, err := SetupWithOptions(TestSetupOptions())
	require.NoError(t, err, "setup should succeed")

	// Create prover and verifier
	prover := ProverFromSetup(setup)
	verifier := NewVerifier(setup.VerifyingKey)

	// Test parameters - simulate a TSS signer
	privateKeyBytes, _ := hex.DecodeString("0000000000000000000000000000000000000000000000000000000000003039") // 12345 padded
	privKey, pubKey := btcec.PrivKeyFromBytes(privateKeyBytes)

	btcqAddress := "qbtc1testaddress123"
	chainID := "qbtc-test-1"

	// Compute address hash from public key
	compressedPubKey := pubKey.SerializeCompressed()
	addressHash, err := PublicKeyToAddressHash(compressedPubKey)
	require.NoError(t, err, "should compute address hash")

	// Compute binding values
	btcqAddressHash := HashBTCQAddress(btcqAddress)
	chainIDHash := ComputeChainIDHash(chainID)

	// Compute the claim message (this is what TSS would sign)
	messageHash := ComputeClaimMessage(addressHash, btcqAddressHash, chainIDHash)
	t.Logf("Message to sign: %s", hex.EncodeToString(messageHash[:]))

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

	t.Run("valid signature proof should verify", func(t *testing.T) {
		// Generate proof
		proof, err := prover.GenerateProof(ProofParams{
			SignatureR:      sigR,
			SignatureS:      sigS,
			PublicKeyX:      pubKey.X(),
			PublicKeyY:      pubKey.Y(),
			MessageHash:     messageHash,
			AddressHash:     addressHash,
			BTCQAddressHash: btcqAddressHash,
			ChainID:         chainIDHash,
		})
		require.NoError(t, err, "proof generation should succeed")
		require.NotEmpty(t, proof.ProofData, "proof data should not be empty")

		// Verify proof
		err = verifier.VerifyProof(proof, VerificationParams{
			MessageHash:     messageHash,
			AddressHash:     addressHash,
			BTCQAddressHash: btcqAddressHash,
			ChainID:         chainIDHash,
		})
		require.NoError(t, err, "valid proof should verify")
	})

	t.Run("proof with wrong message hash should fail", func(t *testing.T) {
		// Generate valid proof
		proof, err := prover.GenerateProof(ProofParams{
			SignatureR:      sigR,
			SignatureS:      sigS,
			PublicKeyX:      pubKey.X(),
			PublicKeyY:      pubKey.Y(),
			MessageHash:     messageHash,
			AddressHash:     addressHash,
			BTCQAddressHash: btcqAddressHash,
			ChainID:         chainIDHash,
		})
		require.NoError(t, err)

		// Try to verify with different message hash
		wrongMessageHash := messageHash
		wrongMessageHash[0] ^= 0xFF

		err = verifier.VerifyProof(proof, VerificationParams{
			MessageHash:     wrongMessageHash,
			AddressHash:     addressHash,
			BTCQAddressHash: btcqAddressHash,
			ChainID:         chainIDHash,
		})
		require.Error(t, err, "proof with wrong message hash should fail")
	})

	t.Run("proof with wrong address hash should fail", func(t *testing.T) {
		proof, err := prover.GenerateProof(ProofParams{
			SignatureR:      sigR,
			SignatureS:      sigS,
			PublicKeyX:      pubKey.X(),
			PublicKeyY:      pubKey.Y(),
			MessageHash:     messageHash,
			AddressHash:     addressHash,
			BTCQAddressHash: btcqAddressHash,
			ChainID:         chainIDHash,
		})
		require.NoError(t, err)

		wrongAddressHash := addressHash
		wrongAddressHash[0] ^= 0xFF

		err = verifier.VerifyProof(proof, VerificationParams{
			MessageHash:     messageHash,
			AddressHash:     wrongAddressHash,
			BTCQAddressHash: btcqAddressHash,
			ChainID:         chainIDHash,
		})
		require.Error(t, err, "proof with wrong address hash should fail")
	})

	t.Run("front-running attack should fail", func(t *testing.T) {
		proof, err := prover.GenerateProof(ProofParams{
			SignatureR:      sigR,
			SignatureS:      sigS,
			PublicKeyX:      pubKey.X(),
			PublicKeyY:      pubKey.Y(),
			MessageHash:     messageHash,
			AddressHash:     addressHash,
			BTCQAddressHash: btcqAddressHash,
			ChainID:         chainIDHash,
		})
		require.NoError(t, err)

		// Attacker tries to redirect to their address
		attackerHash := HashBTCQAddress("qbtc1attacker")

		err = verifier.VerifyProof(proof, VerificationParams{
			MessageHash:     messageHash,
			AddressHash:     addressHash,
			BTCQAddressHash: attackerHash,
			ChainID:         chainIDHash,
		})
		require.Error(t, err, "front-running attack should fail")
	})

	t.Run("cross-chain replay should fail", func(t *testing.T) {
		proof, err := prover.GenerateProof(ProofParams{
			SignatureR:      sigR,
			SignatureS:      sigS,
			PublicKeyX:      pubKey.X(),
			PublicKeyY:      pubKey.Y(),
			MessageHash:     messageHash,
			AddressHash:     addressHash,
			BTCQAddressHash: btcqAddressHash,
			ChainID:         chainIDHash,
		})
		require.NoError(t, err)

		wrongChainIDHash := ComputeChainIDHash("other-chain-1")

		err = verifier.VerifyProof(proof, VerificationParams{
			MessageHash:     messageHash,
			AddressHash:     addressHash,
			BTCQAddressHash: btcqAddressHash,
			ChainID:         wrongChainIDHash,
		})
		require.Error(t, err, "cross-chain replay should fail")
	})
}

// TestComputeClaimMessage tests the deterministic message format.
func TestComputeClaimMessage(t *testing.T) {
	addressHash := [20]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20}
	btcqAddressHash := sha256.Sum256([]byte("qbtc1test"))
	chainIDHash := ComputeChainIDHash("qbtc-1")

	// Compute message
	msg1 := ComputeClaimMessage(addressHash, btcqAddressHash, chainIDHash)

	// Should be deterministic
	msg2 := ComputeClaimMessage(addressHash, btcqAddressHash, chainIDHash)
	require.Equal(t, msg1, msg2, "message should be deterministic")

	// Different inputs should produce different messages
	differentAddressHash := addressHash
	differentAddressHash[0] = 0xFF
	msg3 := ComputeClaimMessage(differentAddressHash, btcqAddressHash, chainIDHash)
	require.NotEqual(t, msg1, msg3, "different address should produce different message")

	differentBtcqHash := HashBTCQAddress("qbtc1different")
	msg4 := ComputeClaimMessage(addressHash, differentBtcqHash, chainIDHash)
	require.NotEqual(t, msg1, msg4, "different btcq address should produce different message")

	differentChainID := ComputeChainIDHash("other-chain")
	msg5 := ComputeClaimMessage(addressHash, btcqAddressHash, differentChainID)
	require.NotEqual(t, msg1, msg5, "different chain ID should produce different message")
}

// TestVerifyClaimMessage tests message verification.
func TestVerifyClaimMessage(t *testing.T) {
	addressHash := [20]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20}
	btcqAddressHash := HashBTCQAddress("qbtc1test")
	chainIDHash := ComputeChainIDHash("qbtc-1")

	messageHash := ComputeClaimMessage(addressHash, btcqAddressHash, chainIDHash)

	// Valid verification
	require.True(t, VerifyClaimMessage(messageHash, addressHash, btcqAddressHash, chainIDHash))

	// Wrong message hash
	wrongMessageHash := messageHash
	wrongMessageHash[0] ^= 0xFF
	require.False(t, VerifyClaimMessage(wrongMessageHash, addressHash, btcqAddressHash, chainIDHash))

	// Wrong parameters
	wrongAddressHash := addressHash
	wrongAddressHash[0] ^= 0xFF
	require.False(t, VerifyClaimMessage(messageHash, wrongAddressHash, btcqAddressHash, chainIDHash))
}

// TestSignatureVerifierImmutability tests that the global signature verifier cannot be re-registered.
func TestSignatureVerifierImmutability(t *testing.T) {
	ClearVerifierForTesting()
	defer ClearVerifierForTesting()

	// This test is fast - just tests registration, not circuit compilation
	setup, err := SetupWithOptions(TestSetupOptions())
	if err != nil {
		t.Skip("skipping - setup failed")
	}

	vkBytes, err := SerializeVerifyingKey(setup.VerifyingKey)
	require.NoError(t, err)

	// First registration should succeed
	err = RegisterVerifier(vkBytes)
	require.NoError(t, err, "first registration should succeed")

	require.True(t, IsVerifierInitialized(), "verifier should be initialized")

	// Second registration should fail
	err = RegisterVerifier(vkBytes)
	require.Error(t, err, "second registration should fail")
	require.ErrorIs(t, err, ErrVerifierAlreadyInitialized)
}

// TestSignatureProofSerialization tests proof serialization round-trip.
func TestSignatureProofSerialization(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping in short mode")
	}

	setup, err := SetupWithOptions(TestSetupOptions())
	require.NoError(t, err)

	prover := ProverFromSetup(setup)

	// Create test signature - use a typical private key (not edge case like 1)
	privateKeyBytes, _ := hex.DecodeString("0000000000000000000000000000000000000000000000000000000000004567")
	privKey, pubKey := btcec.PrivKeyFromBytes(privateKeyBytes)

	compressedPubKey := pubKey.SerializeCompressed()
	addressHash, err := PublicKeyToAddressHash(compressedPubKey)
	require.NoError(t, err)

	btcqAddressHash := HashBTCQAddress("qbtc1test")
	chainIDHash := ComputeChainIDHash("test-chain")
	messageHash := ComputeClaimMessage(addressHash, btcqAddressHash, chainIDHash)

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
		BTCQAddressHash: btcqAddressHash,
		ChainID:         chainIDHash,
	})
	require.NoError(t, err)

	// Serialize
	protoBytes := proof.ToProtoZKProof()
	require.NotEmpty(t, protoBytes)

	// Deserialize
	proof2, err := ProofFromProtoZKProof(protoBytes)
	require.NoError(t, err)
	require.Equal(t, proof.ProofData, proof2.ProofData)
	require.Equal(t, proof.PublicInputs, proof2.PublicInputs)
}

// TestSignatureVerifierGlobalFlow tests the global verifier registration and usage.
func TestSignatureVerifierGlobalFlow(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping in short mode")
	}

	ClearVerifierForTesting()
	defer ClearVerifierForTesting()

	// Setup
	setup, err := SetupWithOptions(TestSetupOptions())
	require.NoError(t, err)

	vkBytes, err := SerializeVerifyingKey(setup.VerifyingKey)
	require.NoError(t, err)

	// Register global verifier
	err = RegisterVerifier(vkBytes)
	require.NoError(t, err)

	// Create prover
	prover := ProverFromSetup(setup)

	// Test data
	privateKeyBytes, _ := hex.DecodeString("0000000000000000000000000000000000000000000000000000000000000042")
	privKey, pubKey := btcec.PrivKeyFromBytes(privateKeyBytes)

	compressedPubKey := pubKey.SerializeCompressed()
	addressHash, _ := PublicKeyToAddressHash(compressedPubKey)
	btcqAddressHash := HashBTCQAddress("qbtc1global_test")
	chainIDHash := ComputeChainIDHash("qbtc-1")
	messageHash := ComputeClaimMessage(addressHash, btcqAddressHash, chainIDHash)

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
		BTCQAddressHash: btcqAddressHash,
		ChainID:         chainIDHash,
	})
	require.NoError(t, err)

	// Verify using global verifier
	err = VerifyProofGlobal(proof, VerificationParams{
		MessageHash:     messageHash,
		AddressHash:     addressHash,
		BTCQAddressHash: btcqAddressHash,
		ChainID:         chainIDHash,
	})
	require.NoError(t, err, "global verification should succeed")
}

// TestMessageVersioning ensures the version string is included in the message.
func TestMessageVersioning(t *testing.T) {
	addressHash := [20]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20}
	btcqAddressHash := HashBTCQAddress("qbtc1test")
	chainIDHash := ComputeChainIDHash("qbtc-1")

	// The current version
	require.Equal(t, "qbtc-claim-v1", ClaimMessageVersion)

	// Message should include the version
	msg := ComputeClaimMessage(addressHash, btcqAddressHash, chainIDHash)

	// Manually compute expected hash
	data := make([]byte, 0, 20+32+8+len(ClaimMessageVersion))
	data = append(data, addressHash[:]...)
	data = append(data, btcqAddressHash[:]...)
	data = append(data, chainIDHash[:]...)
	data = append(data, []byte(ClaimMessageVersion)...)
	expected := sha256.Sum256(data)

	require.Equal(t, expected, msg, "message should match expected format")
}

