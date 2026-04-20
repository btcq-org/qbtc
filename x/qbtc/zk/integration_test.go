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
// 4. Verification with correct params (valid claim)
// 5. Verification with wrong params (attack scenarios)
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
	err = InitializeVerifier(vkBytes)
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
	qbtcAddressHash := HashQBTCAddress(claimerAddress)
	chainIDHash := ComputeChainIDHash(chainID)

	// Compute the claim message (this is what TSS signs)
	messageHash := ComputeClaimMessage(addressHash, qbtcAddressHash, chainIDHash)

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
		QBTCAddressHash: qbtcAddressHash,
		ChainID:         chainIDHash,
	})
	require.NoError(t, err, "proof generation should succeed")

	// Step 4: Verify proof bytes are valid
	t.Log("Step 4: Checking proof bytes...")
	require.NotEmpty(t, proof)

	// Step 5: Verify proof using global verifier (as done by handler)
	t.Log("Step 5: Verifying proof...")
	err = VerifyProofGlobal(proof, VerificationParams{
		MessageHash:     messageHash,
		AddressHash:     addressHash,
		QBTCAddressHash: qbtcAddressHash,
		ChainID:         chainIDHash,
	})
	require.NoError(t, err, "valid proof should verify via global verifier")

	// Step 6: Test attack scenarios
	t.Log("Step 6: Testing attack scenarios...")

	t.Run("front-running attack fails", func(t *testing.T) {
		// Attacker sees the proof and tries to claim to their address
		attackerAddress := "qbtc1attacker_evil"
		attackerAddressHash := HashQBTCAddress(attackerAddress)
		// Recompute message hash with attacker's address
		attackerMessageHash := ComputeClaimMessage(addressHash, attackerAddressHash, chainIDHash)

		err := VerifyProofGlobal(proof, VerificationParams{
			MessageHash:     attackerMessageHash,
			AddressHash:     addressHash,
			QBTCAddressHash: attackerAddressHash, // Different claimer
			ChainID:         chainIDHash,
		})
		require.Error(t, err, "front-running attack should fail")
	})

	t.Run("cross-chain replay attack fails", func(t *testing.T) {
		// Attacker tries to replay proof on different chain
		differentChainHash := ComputeChainIDHash("other-chain-1")
		differentMessageHash := ComputeClaimMessage(addressHash, qbtcAddressHash, differentChainHash)

		err := VerifyProofGlobal(proof, VerificationParams{
			MessageHash:     differentMessageHash,
			AddressHash:     addressHash,
			QBTCAddressHash: qbtcAddressHash,
			ChainID:         differentChainHash, // Different chain
		})
		require.Error(t, err, "cross-chain replay should fail")
	})

	t.Run("claiming different BTC address fails", func(t *testing.T) {
		// Attacker tries to claim for a different BTC address
		differentAddressHash := addressHash
		differentAddressHash[0] ^= 0xFF
		differentMessageHash := ComputeClaimMessage(differentAddressHash, qbtcAddressHash, chainIDHash)

		err := VerifyProofGlobal(proof, VerificationParams{
			MessageHash:     differentMessageHash,
			AddressHash:     differentAddressHash, // Different BTC address
			QBTCAddressHash: qbtcAddressHash,
			ChainID:         chainIDHash,
		})
		require.Error(t, err, "claiming different BTC address should fail")
	})

}

// TestVerifierNotInitialized tests behavior when verifier is not initialized.
func TestVerifierNotInitialized(t *testing.T) {
	ClearVerifierForTesting()

	require.False(t, IsVerifierInitialized(), "verifier should not be initialized")

	_, err := GetVerifier()
	require.Error(t, err, "GetVerifier should fail when not initialized")

	dummyProof := make([]byte, 200)
	err = VerifyProofGlobal(dummyProof, VerificationParams{})
	require.Error(t, err, "VerifyProofGlobal should fail when verifier not initialized")
	require.Contains(t, err.Error(), "not initialized")
}
