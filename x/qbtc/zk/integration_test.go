//go:build testing

package zk

import (
	"math/big"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/ecdsa"
	"github.com/stretchr/testify/require"
)

// TestFullClaimFlow_Integration tests the complete flow from proof generation
// through verification, simulating the on-chain claim process with TSS-compatible
// signature-based proofs.
//
// This test covers:
// 1. Setup with test SRS
// 2. Signing the claim message (simulating TSS)
// 3. Proof generation for a valid claim
// 4. Serialization/deserialization round-trip (as would happen in tx)
// 5. Verification with correct params (valid claim)
// 6. Verification with wrong params (attack scenarios)
func TestFullClaimFlow_Integration(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	// Clear any previous state
	ClearVerifierForTesting()

	// Step 1: Setup (simulates genesis initialization)
	t.Log("Step 1: Running PLONK setup...")
	setup, err := SetupWithOptions(TestSetupOptions())
	require.NoError(t, err, "setup should succeed")

	// Serialize VK (as would be stored in genesis)
	vkBytes, err := SerializeVerifyingKey(setup.VerifyingKey)
	require.NoError(t, err, "VK serialization should succeed")

	// Register verifier from VK bytes (as done in InitGenesis)
	err = RegisterVerifier(vkBytes)
	require.NoError(t, err, "verifier registration should succeed")

	// Create prover (this would be done by the zkprover tool)
	prover := ProverFromSetup(setup)

	// Test parameters (simulating a real user with TSS signer)
	// Create a BTC private key (would be managed by TSS in production)
	privateKeyBytes := make([]byte, 32)
	pkInt, _ := new(big.Int).SetString("12345678901234567890", 10)
	pkInt.FillBytes(privateKeyBytes)
	btcPrivKey, _ := btcec.PrivKeyFromBytes(privateKeyBytes)

	claimerAddress := "qbtc1realuser123abc"
	chainID := "qbtc-mainnet-1"

	// Compute derived values
	addressHash, err := PublicKeyToAddressHash(btcPrivKey.PubKey().SerializeCompressed())
	require.NoError(t, err, "should compute address hash")
	btcqAddressHash := HashBTCQAddress(claimerAddress)
	chainIDHash := ComputeChainIDHash(chainID)

	// Compute the claim message (this is what TSS signs)
	messageHash := ComputeClaimMessage(addressHash, btcqAddressHash, chainIDHash)

	// Step 2: Sign the message (simulating TSS)
	t.Log("Step 2: Signing claim message (TSS simulation)...")
	sig := ecdsa.Sign(btcPrivKey, messageHash[:])

	// Parse R and S from DER-encoded signature
	sigBytes := sig.Serialize()
	rLen := int(sigBytes[3])
	rBytes := sigBytes[4 : 4+rLen]
	sLen := int(sigBytes[4+rLen+1])
	sBytes := sigBytes[4+rLen+2 : 4+rLen+2+sLen]

	// Remove leading zeros (DER uses signed integers)
	if len(rBytes) > 0 && rBytes[0] == 0 {
		rBytes = rBytes[1:]
	}
	if len(sBytes) > 0 && sBytes[0] == 0 {
		sBytes = sBytes[1:]
	}

	sigR := new(big.Int).SetBytes(rBytes)
	sigS := new(big.Int).SetBytes(sBytes)

	// Step 3: Generate proof (done by user's zkprover tool)
	t.Log("Step 3: Generating proof...")
	pubKey := btcPrivKey.PubKey()
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

	// Step 4: Serialize proof for transmission (as in tx)
	t.Log("Step 4: Serializing proof for tx...")
	protoBytes := proof.ToProtoZKProof()
	require.NotEmpty(t, protoBytes)

	// Step 5: Deserialize proof (as done by handler)
	t.Log("Step 5: Deserializing proof from tx...")
	deserializedProof, err := ProofFromProtoZKProof(protoBytes)
	require.NoError(t, err, "proof deserialization should succeed")

	// Step 6: Verify proof using global verifier (as done by handler)
	t.Log("Step 6: Verifying proof...")
	err = VerifyProofGlobal(deserializedProof, VerificationParams{
		MessageHash:     messageHash,
		AddressHash:     addressHash,
		BTCQAddressHash: btcqAddressHash,
		ChainID:         chainIDHash,
	})
	require.NoError(t, err, "valid proof should verify via global verifier")

	// Step 7: Test attack scenarios
	t.Log("Step 7: Testing attack scenarios...")

	t.Run("front-running attack fails", func(t *testing.T) {
		// Attacker sees the proof and tries to claim to their address
		attackerAddress := "qbtc1attacker_evil"
		attackerAddressHash := HashBTCQAddress(attackerAddress)
		// Recompute message hash with attacker's address
		attackerMessageHash := ComputeClaimMessage(addressHash, attackerAddressHash, chainIDHash)

		err := VerifyProofGlobal(deserializedProof, VerificationParams{
			MessageHash:     attackerMessageHash,
			AddressHash:     addressHash,
			BTCQAddressHash: attackerAddressHash, // Different claimer
			ChainID:         chainIDHash,
		})
		require.Error(t, err, "front-running attack should fail")
	})

	t.Run("cross-chain replay attack fails", func(t *testing.T) {
		// Attacker tries to replay proof on different chain
		differentChainHash := ComputeChainIDHash("other-chain-1")
		differentMessageHash := ComputeClaimMessage(addressHash, btcqAddressHash, differentChainHash)

		err := VerifyProofGlobal(deserializedProof, VerificationParams{
			MessageHash:     differentMessageHash,
			AddressHash:     addressHash,
			BTCQAddressHash: btcqAddressHash,
			ChainID:         differentChainHash, // Different chain
		})
		require.Error(t, err, "cross-chain replay should fail")
	})

	t.Run("claiming different BTC address fails", func(t *testing.T) {
		// Attacker tries to claim for a different BTC address
		differentAddressHash := addressHash
		differentAddressHash[0] ^= 0xFF
		differentMessageHash := ComputeClaimMessage(differentAddressHash, btcqAddressHash, chainIDHash)

		err := VerifyProofGlobal(deserializedProof, VerificationParams{
			MessageHash:     differentMessageHash,
			AddressHash:     differentAddressHash, // Different BTC address
			BTCQAddressHash: btcqAddressHash,
			ChainID:         chainIDHash,
		})
		require.Error(t, err, "claiming different BTC address should fail")
	})

	// Cleanup
	ClearVerifierForTesting()
}

// TestVerifierNotInitialized tests behavior when verifier is not initialized.
func TestVerifierNotInitialized(t *testing.T) {
	ClearVerifierForTesting()
	defer ClearVerifierForTesting()

	require.False(t, IsVerifierInitialized(), "verifier should not be initialized")

	_, err := GetVerifier()
	require.Error(t, err, "GetVerifier should fail when not initialized")

	// Create a dummy proof
	dummyProof := &Proof{
		ProofData:    make([]byte, 200),
		PublicInputs: make([]byte, 100),
	}

	err = VerifyProofGlobal(dummyProof, VerificationParams{})
	require.Error(t, err, "VerifyProofGlobal should fail when verifier not initialized")
	require.Contains(t, err.Error(), "not initialized")
}

// TestVerifierImmutability tests that the verifier cannot be re-registered
// after initial registration. This is a critical security property.
func TestVerifierImmutability(t *testing.T) {
	ClearVerifierForTesting()
	defer ClearVerifierForTesting()

	// Create a test VK
	setup, err := SetupWithOptions(TestSetupOptions())
	require.NoError(t, err)

	vkBytes, err := SerializeVerifyingKey(setup.VerifyingKey)
	require.NoError(t, err)

	// First registration should succeed
	err = RegisterVerifier(vkBytes)
	require.NoError(t, err, "first registration should succeed")

	require.True(t, IsVerifierInitialized())

	// Second registration should fail
	err = RegisterVerifier(vkBytes)
	require.Error(t, err, "second registration should fail")
	require.ErrorIs(t, err, ErrVerifierAlreadyInitialized)

	// Third attempt should also fail
	err = RegisterVerifier(vkBytes)
	require.Error(t, err, "third registration should also fail")
}
