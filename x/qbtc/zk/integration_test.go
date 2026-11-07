//go:build testing

package zk

import (
	"math/big"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/stretchr/testify/require"
)

// TestFullClaimFlow_Integration tests the complete flow from proof generation
// through verification, simulating the on-chain claim process.
//
// This test covers:
// 1. Setup with test SRS
// 2. Signing the claim text in a wallet (BIP-137)
// 3. Proof generation for a valid claim
// 4. Verification with correct params (valid claim)
// 5. Verification with wrong params (attack scenarios)
func TestFullClaimFlow_Integration(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	ClearVerifierForTesting()

	// Step 1: Setup (simulates genesis initialization)
	t.Log("Step 1: Running PLONK setup...")
	setup, err := SetupWithOptions(TestSetupOptions())
	require.NoError(t, err, "setup should succeed")

	vkBytes, err := SerializeVerifyingKey(setup.VerifyingKey)
	require.NoError(t, err, "VK serialization should succeed")

	err = InitializeVerifier(vkBytes)
	require.NoError(t, err, "verifier registration should succeed")

	prover := ProverFromSetup(setup)

	privateKeyBytes := make([]byte, 32)
	pkInt, _ := new(big.Int).SetString("12345678901234567890", 10)
	pkInt.FillBytes(privateKeyBytes)
	btcPrivKey, btcPubKey := btcec.PrivKeyFromBytes(privateKeyBytes)

	claimerAddress := "qbtc1realuser123abc"
	chainID := "qbtc-mainnet-1"
	bitcoinAddress := p2pkhAddressForTest(btcPubKey)

	// Step 2: Sign the claim text (the user's wallet does this)
	t.Log("Step 2: Signing claim message (wallet simulation)...")
	params, _, pubKeyHashSHA256 := signClaimForTest(t, btcPrivKey, chainID, bitcoinAddress, claimerAddress)

	// Step 3: Generate proof (done by the user's zkprover tool)
	t.Log("Step 3: Generating proof...")
	proof, err := prover.GenerateProof(params)
	require.NoError(t, err, "proof generation should succeed")
	require.NotEmpty(t, proof)

	// Step 4: Verify proof using the global verifier (as done by the handler)
	t.Log("Step 4: Verifying proof...")
	valid := VerificationParams{
		ChainID:          chainID,
		BitcoinAddress:   bitcoinAddress,
		QBTCAddress:      claimerAddress,
		PubKeyHashSHA256: pubKeyHashSHA256,
	}
	require.NoError(t, VerifyProofGlobal(proof, valid), "valid proof should verify via global verifier")

	// Step 5: Attack scenarios
	t.Log("Step 5: Testing attack scenarios...")

	t.Run("front-running attack fails", func(t *testing.T) {
		p := valid
		p.QBTCAddress = "qbtc1attacker_evil"
		require.Error(t, VerifyProofGlobal(proof, p), "front-running attack should fail")
	})

	t.Run("cross-chain replay attack fails", func(t *testing.T) {
		p := valid
		p.ChainID = "other-chain-1"
		require.Error(t, VerifyProofGlobal(proof, p), "cross-chain replay should fail")
	})

	t.Run("claiming different BTC address fails", func(t *testing.T) {
		other, err := btcec.NewPrivateKey()
		require.NoError(t, err)
		p := valid
		p.BitcoinAddress = p2pkhAddressForTest(other.PubKey())
		require.Error(t, VerifyProofGlobal(proof, p), "claiming different BTC address should fail")
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
