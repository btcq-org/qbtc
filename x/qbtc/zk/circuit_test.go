//go:build testing

package zk

import (
	"math/big"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestBTCAddressCircuit_EndToEnd tests the complete proof generation and verification flow.
// This is a critical security test that ensures:
// 1. Valid proofs are accepted
// 2. Proofs with wrong address hash are rejected
// 3. Proofs with wrong btcq address are rejected
// 4. Proofs with wrong chain ID are rejected
func TestBTCAddressCircuit_EndToEnd(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping end-to-end circuit test in short mode")
	}

	// Setup with test SRS (WARNING: test mode only!)
	t.Log("Running PLONK setup (this may take a minute)...")
	setup, err := SetupWithOptions(TestSetupOptions())
	require.NoError(t, err, "setup should succeed")

	// Create prover and verifier
	prover := ProverFromSetup(setup)
	verifier := NewVerifier(setup.VerifyingKey)

	// Test parameters
	privateKey := big.NewInt(12345) // Test private key
	btcqAddress := "qbtc1testaddress123"
	chainID := "qbtc-test-1"

	// Compute address hash from private key
	addressHash, err := PrivateKeyToAddressHash(privateKey)
	require.NoError(t, err, "should compute address hash")

	// Compute binding values
	btcqAddressHash := HashBTCQAddress(btcqAddress)
	chainIDHash := ComputeChainIDHash(chainID)

	t.Run("valid proof should verify", func(t *testing.T) {
		// Generate proof
		proof, err := prover.GenerateProof(ProofParams{
			PrivateKey:      privateKey,
			AddressHash:     addressHash,
			BTCQAddressHash: btcqAddressHash,
			ChainID:         chainIDHash,
		})
		require.NoError(t, err, "proof generation should succeed")
		require.NotEmpty(t, proof.ProofData, "proof data should not be empty")

		// Verify proof
		err = verifier.VerifyProof(proof, VerificationParams{
			AddressHash:     addressHash,
			BTCQAddressHash: btcqAddressHash,
			ChainID:         chainIDHash,
		})
		require.NoError(t, err, "valid proof should verify")
	})

	t.Run("proof with wrong address hash should fail", func(t *testing.T) {
		// Generate valid proof
		proof, err := prover.GenerateProof(ProofParams{
			PrivateKey:      privateKey,
			AddressHash:     addressHash,
			BTCQAddressHash: btcqAddressHash,
			ChainID:         chainIDHash,
		})
		require.NoError(t, err)

		// Try to verify with different address hash
		wrongAddressHash := addressHash
		wrongAddressHash[0] ^= 0xFF // Flip bits

		err = verifier.VerifyProof(proof, VerificationParams{
			AddressHash:     wrongAddressHash,
			BTCQAddressHash: btcqAddressHash,
			ChainID:         chainIDHash,
		})
		require.Error(t, err, "proof with wrong address hash should fail verification")
	})

	t.Run("proof with wrong btcq address should fail", func(t *testing.T) {
		// Generate valid proof
		proof, err := prover.GenerateProof(ProofParams{
			PrivateKey:      privateKey,
			AddressHash:     addressHash,
			BTCQAddressHash: btcqAddressHash,
			ChainID:         chainIDHash,
		})
		require.NoError(t, err)

		// Try to verify with different btcq address (front-running attack)
		wrongBTCQHash := HashBTCQAddress("qbtc1attacker_address")

		err = verifier.VerifyProof(proof, VerificationParams{
			AddressHash:     addressHash,
			BTCQAddressHash: wrongBTCQHash,
			ChainID:         chainIDHash,
		})
		require.Error(t, err, "proof with wrong btcq address should fail (anti-frontrunning)")
	})

	t.Run("proof with wrong chain ID should fail", func(t *testing.T) {
		// Generate valid proof
		proof, err := prover.GenerateProof(ProofParams{
			PrivateKey:      privateKey,
			AddressHash:     addressHash,
			BTCQAddressHash: btcqAddressHash,
			ChainID:         chainIDHash,
		})
		require.NoError(t, err)

		// Try to verify with different chain ID (cross-chain replay attack)
		wrongChainIDHash := ComputeChainIDHash("other-chain-1")

		err = verifier.VerifyProof(proof, VerificationParams{
			AddressHash:     addressHash,
			BTCQAddressHash: btcqAddressHash,
			ChainID:         wrongChainIDHash,
		})
		require.Error(t, err, "proof with wrong chain ID should fail (anti-replay)")
	})

	t.Run("proof for wrong private key should fail", func(t *testing.T) {
		// Try to generate a proof with wrong private key but correct address hash
		// This should fail during proof generation because the circuit constraints won't be satisfied
		wrongPrivateKey := big.NewInt(99999)

		// This will fail because the private key doesn't produce the claimed address hash
		_, err := prover.GenerateProof(ProofParams{
			PrivateKey:      wrongPrivateKey,
			AddressHash:     addressHash, // Address hash for different key
			BTCQAddressHash: btcqAddressHash,
			ChainID:         chainIDHash,
		})
		require.Error(t, err, "proof with wrong private key should fail during generation")
	})
}

// TestVerifierImmutability tests that the global verifier cannot be re-registered.
func TestVerifierImmutability(t *testing.T) {
	// Clear any existing state first
	ClearVerifierForTesting()

	// Create a test VK
	setup, err := SetupWithOptions(TestSetupOptions())
	if err != nil {
		t.Skip("skipping verifier test - setup failed")
	}

	vkBytes, err := SerializeVerifyingKey(setup.VerifyingKey)
	require.NoError(t, err)

	// First registration should succeed
	err = RegisterVerifier(vkBytes)
	require.NoError(t, err, "first registration should succeed")

	// Verify it's initialized
	require.True(t, IsVerifierInitialized(), "verifier should be initialized")

	// Second registration should fail
	err = RegisterVerifier(vkBytes)
	require.Error(t, err, "second registration should fail")
	require.ErrorIs(t, err, ErrVerifierAlreadyInitialized)

	// RegisterVerifierFromVK should also fail
	err = RegisterVerifierFromVK(setup.VerifyingKey)
	require.Error(t, err, "RegisterVerifierFromVK should fail when already initialized")
	require.ErrorIs(t, err, ErrVerifierAlreadyInitialized)

	// Clean up
	ClearVerifierForTesting()
}

// TestProofSerialization tests proof serialization round-trip.
func TestProofSerialization(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping proof serialization test in short mode")
	}

	// Setup
	setup, err := SetupWithOptions(TestSetupOptions())
	require.NoError(t, err)

	prover := ProverFromSetup(setup)

	// Generate a proof
	privateKey := big.NewInt(42)
	addressHash, err := PrivateKeyToAddressHash(privateKey)
	require.NoError(t, err)

	proof, err := prover.GenerateProof(ProofParams{
		PrivateKey:      privateKey,
		AddressHash:     addressHash,
		BTCQAddressHash: HashBTCQAddress("qbtc1test"),
		ChainID:         ComputeChainIDHash("test-chain"),
	})
	require.NoError(t, err)

	// Serialize to proto format
	protoBytes := proof.ToProtoZKProof()
	require.NotEmpty(t, protoBytes)

	// Deserialize back
	proof2, err := ProofFromProtoZKProof(protoBytes)
	require.NoError(t, err)
	require.Equal(t, proof.ProofData, proof2.ProofData)
	require.Equal(t, proof.PublicInputs, proof2.PublicInputs)
}

// TestProofFromProtoZKProof_InvalidInput tests that malformed proofs are rejected.
func TestProofFromProtoZKProof_InvalidInput(t *testing.T) {
	testCases := []struct {
		name    string
		data    []byte
		wantErr string
	}{
		{
			name:    "empty data",
			data:    []byte{},
			wantErr: "too short",
		},
		{
			name:    "too short",
			data:    []byte{0, 0, 0},
			wantErr: "too short",
		},
		{
			name:    "proof length too small",
			data:    []byte{0, 0, 0, 50, 1, 2, 3}, // claims 50 bytes but min is 100
			wantErr: "below minimum",
		},
		{
			name:    "proof length exceeds data",
			data:    append([]byte{0, 0, 1, 0}, make([]byte, 100)...), // claims 256 bytes but only 100 provided
			wantErr: "truncated",
		},
		{
			name:    "proof length too large",
			data:    append([]byte{0x10, 0, 0, 0}, make([]byte, 200)...), // claims ~268MB
			wantErr: "exceeds maximum",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ProofFromProtoZKProof(tc.data)
			require.Error(t, err)
			require.Contains(t, err.Error(), tc.wantErr)
		})
	}
}

