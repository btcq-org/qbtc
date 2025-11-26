//go:build testing

// Package main provides integration tests for the DKLS TSS + ZK proof system.
// These tests demonstrate the complete flow from distributed key generation
// through threshold signing and zero-knowledge proof verification.
package main

import (
	"math/big"
	"testing"

	"github.com/btcq-org/qbtc/x/qbtc/zk"
	"github.com/ethereum/go-ethereum/crypto/secp256k1"
	session "github.com/vultisig/go-wrappers/go-dkls/sessions"
	"github.com/stretchr/testify/require"
)

// TestDKLSTSS_2of2_Keygen tests basic 2-of-2 distributed key generation
func TestDKLSTSS_2of2_Keygen(t *testing.T) {
	t.Log("Running 2-of-2 DKLS keygen...")

	keyshares, err := runKeygen(2, 2)
	require.NoError(t, err, "keygen should succeed")
	require.Len(t, keyshares, 2, "should have 2 keyshares")

	// Get public keys from both shares - they should be identical
	pk1, err := session.DklsKeysharePublicKey(keyshares[0])
	require.NoError(t, err)
	pk2, err := session.DklsKeysharePublicKey(keyshares[1])
	require.NoError(t, err)

	require.Equal(t, pk1, pk2, "both keyshares should have the same public key")
	require.Len(t, pk1, 33, "public key should be 33 bytes (compressed)")

	t.Logf("Generated shared public key: %x", pk1)

	// Cleanup
	for _, share := range keyshares {
		_ = session.DklsKeyshareFree(share)
	}
}

// TestDKLSTSS_2of2_Sign tests basic 2-of-2 threshold signing
func TestDKLSTSS_2of2_Sign(t *testing.T) {
	t.Log("Running 2-of-2 DKLS keygen...")
	keyshares, err := runKeygen(2, 2)
	require.NoError(t, err, "keygen should succeed")
	defer func() {
		for _, share := range keyshares {
			_ = session.DklsKeyshareFree(share)
		}
	}()

	// Create a test message (32 bytes)
	msg := make([]byte, 32)
	for i := range msg {
		msg[i] = byte(i)
	}

	t.Log("Running 2-of-2 DKLS signing...")
	signatures, err := runSign(keyshares, msg)
	require.NoError(t, err, "signing should succeed")
	require.Len(t, signatures, 2, "should have 2 signatures")

	// All parties produce the same signature
	require.Equal(t, signatures[0], signatures[1], "both parties should produce the same signature")

	sig := signatures[0]
	require.Len(t, sig, 65, "signature should be 65 bytes (R || S || V)")

	t.Logf("Generated signature: %x", sig)

	// Verify the signature using go-ethereum's secp256k1
	pk, err := session.DklsKeysharePublicKey(keyshares[0])
	require.NoError(t, err)

	pubKeyX, _ := secp256k1.DecompressPubkey(pk)
	require.NotNil(t, pubKeyX, "should decompress public key")

	r := new(big.Int).SetBytes(sig[:32])
	s := new(big.Int).SetBytes(sig[32:64])

	// Verify using secp256k1
	verified := secp256k1.VerifySignature(pk, msg, append(r.Bytes(), s.Bytes()...))
	require.True(t, verified, "signature should verify")
}

// TestDKLSTSS_ZKProofIntegration tests the complete flow:
// 1. 2-of-2 DKLS keygen
// 2. Sign a ZK claim message
// 3. Generate ZK proof
// 4. Verify ZK proof
func TestDKLSTSS_ZKProofIntegration(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	// Clear any previous verifier state
	zk.ClearVerifierForTesting()
	defer zk.ClearVerifierForTesting()

	// ========================================
	// Step 1: PLONK Setup
	// ========================================
	t.Log("Step 1: Running PLONK setup...")
	setup, err := zk.SetupWithOptions(zk.TestSetupOptions())
	require.NoError(t, err, "PLONK setup should succeed")

	// Register verifier
	vkBytes, err := zk.SerializeVerifyingKey(setup.VerifyingKey)
	require.NoError(t, err)
	err = zk.RegisterVerifier(vkBytes)
	require.NoError(t, err, "verifier registration should succeed")

	prover := zk.ProverFromSetup(setup)

	// ========================================
	// Step 2: 2-of-2 DKLS Keygen
	// ========================================
	t.Log("Step 2: Running 2-of-2 DKLS keygen...")
	keyshares, err := runKeygen(2, 2)
	require.NoError(t, err, "keygen should succeed")
	require.Len(t, keyshares, 2)
	defer func() {
		for _, share := range keyshares {
			_ = session.DklsKeyshareFree(share)
		}
	}()

	// Get shared public key
	pubKeyBytes, err := session.DklsKeysharePublicKey(keyshares[0])
	require.NoError(t, err)
	t.Logf("  Shared public key: %x", pubKeyBytes)

	// ========================================
	// Step 3: Compute Claim Parameters
	// ========================================
	t.Log("Step 3: Computing claim parameters...")

	// Compute address hash from TSS public key
	addressHash, err := zk.PublicKeyToAddressHash(pubKeyBytes)
	require.NoError(t, err, "should compute address hash")
	t.Logf("  Bitcoin address hash: %x", addressHash)

	// Claim parameters
	claimerAddress := "qbtc1dkls_integration_test_address"
	chainID := "qbtc-mainnet-1"
	btcqAddressHash := zk.HashBTCQAddress(claimerAddress)
	chainIDHash := zk.ComputeChainIDHash(chainID)

	// Compute the claim message (this is what TSS signs)
	messageHash := zk.ComputeClaimMessage(addressHash, btcqAddressHash, chainIDHash)
	t.Logf("  Message hash: %x", messageHash)

	// ========================================
	// Step 4: Sign with TSS
	// ========================================
	t.Log("Step 4: Signing claim message with 2-of-2 TSS...")
	signatures, err := runSign(keyshares, messageHash[:])
	require.NoError(t, err, "signing should succeed")

	// All parties produce the same signature
	sig := signatures[0]
	require.Len(t, sig, 65, "signature should be 65 bytes")
	t.Logf("  Signature: %x", sig)

	// Parse R, S from signature (format: R[32] || S[32] || V[1])
	sigR := new(big.Int).SetBytes(sig[:32])
	sigS := new(big.Int).SetBytes(sig[32:64])

	// Decompress public key to get X, Y coordinates
	pubKeyX, pubKeyY := secp256k1.DecompressPubkey(pubKeyBytes)
	require.NotNil(t, pubKeyX, "should decompress public key")

	// ========================================
	// Step 5: Generate ZK Proof
	// ========================================
	t.Log("Step 5: Generating ZK proof...")
	proof, err := prover.GenerateProof(zk.ProofParams{
		SignatureR:      sigR,
		SignatureS:      sigS,
		PublicKeyX:      pubKeyX,
		PublicKeyY:      pubKeyY,
		MessageHash:     messageHash,
		AddressHash:     addressHash,
		BTCQAddressHash: btcqAddressHash,
		ChainID:         chainIDHash,
	})
	require.NoError(t, err, "proof generation should succeed")
	t.Logf("  Proof size: %d bytes", len(proof.ProofData))

	// ========================================
	// Step 6: Serialize/Deserialize Proof (TX Round-trip)
	// ========================================
	t.Log("Step 6: Testing proof serialization round-trip...")
	protoBytes := proof.ToProtoZKProof()
	require.NotEmpty(t, protoBytes)

	deserializedProof, err := zk.ProofFromProtoZKProof(protoBytes)
	require.NoError(t, err, "proof deserialization should succeed")

	// ========================================
	// Step 7: Verify Proof
	// ========================================
	t.Log("Step 7: Verifying ZK proof...")
	err = zk.VerifyProofGlobal(deserializedProof, zk.VerificationParams{
		MessageHash:     messageHash,
		AddressHash:     addressHash,
		BTCQAddressHash: btcqAddressHash,
		ChainID:         chainIDHash,
	})
	require.NoError(t, err, "valid proof should verify")
	t.Log("  ✓ Proof verified successfully!")

	// ========================================
	// Step 8: Test Attack Scenarios
	// ========================================
	t.Log("Step 8: Testing attack scenarios...")

	t.Run("front-running attack fails", func(t *testing.T) {
		// Attacker tries to claim to their address using our proof
		attackerAddress := "qbtc1attacker_evil"
		attackerAddressHash := zk.HashBTCQAddress(attackerAddress)
		attackerMessageHash := zk.ComputeClaimMessage(addressHash, attackerAddressHash, chainIDHash)

		err := zk.VerifyProofGlobal(deserializedProof, zk.VerificationParams{
			MessageHash:     attackerMessageHash,
			AddressHash:     addressHash,
			BTCQAddressHash: attackerAddressHash,
			ChainID:         chainIDHash,
		})
		require.Error(t, err, "front-running attack should fail")
	})

	t.Run("cross-chain replay attack fails", func(t *testing.T) {
		// Attacker tries to replay proof on different chain
		differentChainHash := zk.ComputeChainIDHash("evil-chain-1")
		differentMessageHash := zk.ComputeClaimMessage(addressHash, btcqAddressHash, differentChainHash)

		err := zk.VerifyProofGlobal(deserializedProof, zk.VerificationParams{
			MessageHash:     differentMessageHash,
			AddressHash:     addressHash,
			BTCQAddressHash: btcqAddressHash,
			ChainID:         differentChainHash,
		})
		require.Error(t, err, "cross-chain replay should fail")
	})

	t.Run("claiming different BTC address fails", func(t *testing.T) {
		// Attacker tries to claim a different BTC address
		differentAddressHash := addressHash
		differentAddressHash[0] ^= 0xFF // Flip some bits
		differentMessageHash := zk.ComputeClaimMessage(differentAddressHash, btcqAddressHash, chainIDHash)

		err := zk.VerifyProofGlobal(deserializedProof, zk.VerificationParams{
			MessageHash:     differentMessageHash,
			AddressHash:     differentAddressHash,
			BTCQAddressHash: btcqAddressHash,
			ChainID:         chainIDHash,
		})
		require.Error(t, err, "claiming different BTC address should fail")
	})

	t.Log("All tests passed!")
}

// TestDKLSTSS_2of3_ZKProof tests 2-of-3 threshold scheme with ZK proofs
func TestDKLSTSS_2of3_ZKProof(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	// Clear any previous verifier state
	zk.ClearVerifierForTesting()
	defer zk.ClearVerifierForTesting()

	// PLONK Setup
	t.Log("Setting up PLONK...")
	setup, err := zk.SetupWithOptions(zk.TestSetupOptions())
	require.NoError(t, err)

	vkBytes, err := zk.SerializeVerifyingKey(setup.VerifyingKey)
	require.NoError(t, err)
	err = zk.RegisterVerifier(vkBytes)
	require.NoError(t, err)

	prover := zk.ProverFromSetup(setup)

	// 2-of-3 Keygen
	t.Log("Running 2-of-3 DKLS keygen...")
	keyshares, err := runKeygen(2, 3)
	require.NoError(t, err)
	require.Len(t, keyshares, 3)
	defer func() {
		for _, share := range keyshares {
			_ = session.DklsKeyshareFree(share)
		}
	}()

	// Get public key
	pubKeyBytes, err := session.DklsKeysharePublicKey(keyshares[0])
	require.NoError(t, err)

	// Compute claim parameters
	addressHash, err := zk.PublicKeyToAddressHash(pubKeyBytes)
	require.NoError(t, err)

	claimerAddress := "qbtc1tss_2of3_test"
	chainID := "qbtc-mainnet-1"
	btcqAddressHash := zk.HashBTCQAddress(claimerAddress)
	chainIDHash := zk.ComputeChainIDHash(chainID)
	messageHash := zk.ComputeClaimMessage(addressHash, btcqAddressHash, chainIDHash)

	// Sign with only 2 of 3 parties (parties 1 and 2)
	t.Log("Signing with parties 1 and 2 (2-of-3)...")
	signatures, err := runSign(keyshares[:2], messageHash[:])
	require.NoError(t, err)

	sig := signatures[0]
	sigR := new(big.Int).SetBytes(sig[:32])
	sigS := new(big.Int).SetBytes(sig[32:64])

	pubKeyX, pubKeyY := secp256k1.DecompressPubkey(pubKeyBytes)
	require.NotNil(t, pubKeyX)

	// Generate and verify proof
	t.Log("Generating and verifying ZK proof...")
	proof, err := prover.GenerateProof(zk.ProofParams{
		SignatureR:      sigR,
		SignatureS:      sigS,
		PublicKeyX:      pubKeyX,
		PublicKeyY:      pubKeyY,
		MessageHash:     messageHash,
		AddressHash:     addressHash,
		BTCQAddressHash: btcqAddressHash,
		ChainID:         chainIDHash,
	})
	require.NoError(t, err)

	err = zk.VerifyProofGlobal(proof, zk.VerificationParams{
		MessageHash:     messageHash,
		AddressHash:     addressHash,
		BTCQAddressHash: btcqAddressHash,
		ChainID:         chainIDHash,
	})
	require.NoError(t, err, "2-of-3 TSS proof should verify")

	// Sign with different parties (parties 2 and 3)
	t.Log("Signing with parties 2 and 3 (different 2-of-3 combination)...")
	signatures2, err := runSign(keyshares[1:3], messageHash[:])
	require.NoError(t, err)

	sig2 := signatures2[0]
	sigR2 := new(big.Int).SetBytes(sig2[:32])
	sigS2 := new(big.Int).SetBytes(sig2[32:64])

	proof2, err := prover.GenerateProof(zk.ProofParams{
		SignatureR:      sigR2,
		SignatureS:      sigS2,
		PublicKeyX:      pubKeyX,
		PublicKeyY:      pubKeyY,
		MessageHash:     messageHash,
		AddressHash:     addressHash,
		BTCQAddressHash: btcqAddressHash,
		ChainID:         chainIDHash,
	})
	require.NoError(t, err)

	err = zk.VerifyProofGlobal(proof2, zk.VerificationParams{
		MessageHash:     messageHash,
		AddressHash:     addressHash,
		BTCQAddressHash: btcqAddressHash,
		ChainID:         chainIDHash,
	})
	require.NoError(t, err, "different 2-of-3 combination should also verify")

	t.Log("2-of-3 TSS + ZK proof test passed!")
}

