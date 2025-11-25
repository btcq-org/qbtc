//go:build testing

package zk

import (
	"math/big"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestFullClaimFlow_Integration tests the complete flow from proof generation
// through verification, simulating the on-chain claim process.
//
// This test covers:
// 1. Setup with test SRS
// 2. Proof generation for a valid claim
// 3. Serialization/deserialization round-trip (as would happen in tx)
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
	err = RegisterVerifier(vkBytes)
	require.NoError(t, err, "verifier registration should succeed")

	// Create prover (this would be done by the zkprover tool)
	prover := ProverFromSetup(setup)

	// Test parameters (simulating a real user)
	privateKey, _ := new(big.Int).SetString("12345678901234567890123456789012345678901234567890", 10)
	claimerAddress := "qbtc1realuser123abc"
	chainID := "qbtc-mainnet-1"

	// Compute derived values
	addressHash, err := PrivateKeyToAddressHash(privateKey)
	require.NoError(t, err, "should compute address hash")
	btcqAddressHash := HashBTCQAddress(claimerAddress)
	chainIDHash := ComputeChainIDHash(chainID)

	// Step 2: Generate proof (done by user's zkprover tool)
	t.Log("Step 2: Generating proof...")
	proof, err := prover.GenerateProof(ProofParams{
		PrivateKey:      privateKey,
		AddressHash:     addressHash,
		BTCQAddressHash: btcqAddressHash,
		ChainID:         chainIDHash,
	})
	require.NoError(t, err, "proof generation should succeed")

	// Step 3: Serialize proof for transmission (as in tx)
	t.Log("Step 3: Serializing proof for tx...")
	protoBytes := proof.ToProtoZKProof()
	require.NotEmpty(t, protoBytes)

	// Step 4: Deserialize proof (as done by handler)
	t.Log("Step 4: Deserializing proof from tx...")
	deserializedProof, err := ProofFromProtoZKProof(protoBytes)
	require.NoError(t, err, "proof deserialization should succeed")

	// Step 5: Verify proof using global verifier (as done by handler)
	t.Log("Step 5: Verifying proof...")
	err = VerifyProofGlobal(deserializedProof, VerificationParams{
		AddressHash:     addressHash,
		BTCQAddressHash: btcqAddressHash,
		ChainID:         chainIDHash,
	})
	require.NoError(t, err, "valid proof should verify via global verifier")

	// Step 6: Test attack scenarios
	t.Log("Step 6: Testing attack scenarios...")

	t.Run("front-running attack fails", func(t *testing.T) {
		// Attacker sees the proof and tries to claim to their address
		attackerAddress := "qbtc1attacker_evil"
		attackerAddressHash := HashBTCQAddress(attackerAddress)

		err := VerifyProofGlobal(deserializedProof, VerificationParams{
			AddressHash:     addressHash,
			BTCQAddressHash: attackerAddressHash, // Different claimer
			ChainID:         chainIDHash,
		})
		require.Error(t, err, "front-running attack should fail")
	})

	t.Run("cross-chain replay attack fails", func(t *testing.T) {
		// Attacker tries to replay proof on different chain
		differentChainHash := ComputeChainIDHash("other-chain-1")

		err := VerifyProofGlobal(deserializedProof, VerificationParams{
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

		err := VerifyProofGlobal(deserializedProof, VerificationParams{
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

// TestMultipleClaimsFromSameAddress tests that the same BTC address
// can only be claimed once (simulating the on-chain ClaimedAirdrops check).
// Note: The actual double-claim prevention is in the keeper, not the ZK module.
// This test documents the uniqueness invariant.
func TestMultipleClaimsFromSameAddress(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping in short mode")
	}

	ClearVerifierForTesting()
	defer ClearVerifierForTesting()

	setup, err := SetupWithOptions(TestSetupOptions())
	require.NoError(t, err)

	vkBytes, err := SerializeVerifyingKey(setup.VerifyingKey)
	require.NoError(t, err)
	require.NoError(t, RegisterVerifier(vkBytes))

	prover := ProverFromSetup(setup)

	// Same BTC private key
	privateKey := big.NewInt(999999)
	addressHash, err := PrivateKeyToAddressHash(privateKey)
	require.NoError(t, err)

	chainIDHash := ComputeChainIDHash("qbtc-1")

	// First claim
	claim1Address := "qbtc1user1"
	proof1, err := prover.GenerateProof(ProofParams{
		PrivateKey:      privateKey,
		AddressHash:     addressHash,
		BTCQAddressHash: HashBTCQAddress(claim1Address),
		ChainID:         chainIDHash,
	})
	require.NoError(t, err)

	err = VerifyProofGlobal(proof1, VerificationParams{
		AddressHash:     addressHash,
		BTCQAddressHash: HashBTCQAddress(claim1Address),
		ChainID:         chainIDHash,
	})
	require.NoError(t, err, "first claim should verify")

	// Second claim attempt with different BTCQ address (same BTC address)
	// This would be rejected by the keeper's ClaimedAirdrops check,
	// but the proof itself would still be valid (different claimer binding)
	claim2Address := "qbtc1user2"
	proof2, err := prover.GenerateProof(ProofParams{
		PrivateKey:      privateKey,
		AddressHash:     addressHash,
		BTCQAddressHash: HashBTCQAddress(claim2Address),
		ChainID:         chainIDHash,
	})
	require.NoError(t, err, "can generate proof for different claimer")

	// This proof would verify cryptographically...
	err = VerifyProofGlobal(proof2, VerificationParams{
		AddressHash:     addressHash,
		BTCQAddressHash: HashBTCQAddress(claim2Address),
		ChainID:         chainIDHash,
	})
	require.NoError(t, err, "second proof verifies cryptographically")

	// ...but the keeper would reject it because addressHash is already claimed
	// The uniqueness is enforced by: (btc_address_hash -> claimed) mapping
	// Not by the ZK proof itself

	t.Log("Note: Double-claim prevention is handled by keeper's ClaimedAirdrops, not ZK")
}

// TestProofBindingUniqueness documents the uniqueness guarantees.
// A valid proof is bound to EXACTLY:
// 1. One BTC address (via addressHash derived from private key)
// 2. One BTCQ claimer address (via btcqAddressHash)
// 3. One chain (via chainID)
//
// This triple (btc_address, btcq_address, chain) uniquely identifies a claim.
func TestProofBindingUniqueness(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping in short mode")
	}

	ClearVerifierForTesting()
	defer ClearVerifierForTesting()

	setup, err := SetupWithOptions(TestSetupOptions())
	require.NoError(t, err)

	vkBytes, err := SerializeVerifyingKey(setup.VerifyingKey)
	require.NoError(t, err)
	require.NoError(t, RegisterVerifier(vkBytes))

	prover := ProverFromSetup(setup)

	privateKey := big.NewInt(77777)
	addressHash, err := PrivateKeyToAddressHash(privateKey)
	require.NoError(t, err)

	claimerAddress := "qbtc1claimer"
	chainID := "qbtc-1"

	btcqAddressHash := HashBTCQAddress(claimerAddress)
	chainIDHash := ComputeChainIDHash(chainID)

	proof, err := prover.GenerateProof(ProofParams{
		PrivateKey:      privateKey,
		AddressHash:     addressHash,
		BTCQAddressHash: btcqAddressHash,
		ChainID:         chainIDHash,
	})
	require.NoError(t, err)

	// The proof is bound to this EXACT combination
	err = VerifyProofGlobal(proof, VerificationParams{
		AddressHash:     addressHash,
		BTCQAddressHash: btcqAddressHash,
		ChainID:         chainIDHash,
	})
	require.NoError(t, err)

	// Any change to the binding fails
	testCases := []struct {
		name   string
		modify func(p *VerificationParams)
	}{
		{"different btc address byte 0", func(p *VerificationParams) { p.AddressHash[0] ^= 1 }},
		{"different btc address byte 10", func(p *VerificationParams) { p.AddressHash[10] ^= 1 }},
		{"different btc address byte 19", func(p *VerificationParams) { p.AddressHash[19] ^= 1 }},
		{"different btcq address byte 0", func(p *VerificationParams) { p.BTCQAddressHash[0] ^= 1 }},
		{"different btcq address byte 16", func(p *VerificationParams) { p.BTCQAddressHash[16] ^= 1 }},
		{"different btcq address byte 31", func(p *VerificationParams) { p.BTCQAddressHash[31] ^= 1 }},
		{"different chain id byte 0", func(p *VerificationParams) { p.ChainID[0] ^= 1 }},
		{"different chain id byte 7", func(p *VerificationParams) { p.ChainID[7] ^= 1 }},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			params := VerificationParams{
				AddressHash:     addressHash,
				BTCQAddressHash: btcqAddressHash,
				ChainID:         chainIDHash,
			}
			tc.modify(&params)
			err := VerifyProofGlobal(proof, params)
			require.Error(t, err, "modified params should fail verification")
		})
	}
}

