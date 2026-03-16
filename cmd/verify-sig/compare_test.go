package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/cloudflare/circl/sign/mldsa/mldsa44"
	"github.com/stretchr/testify/require"
	mldsaSession "github.com/vultisig/go-wrappers/mldsa"
)

// TestCompareSignatures generates keys and signs with BOTH libraries,
// then cross-verifies to pinpoint the exact incompatibility.
func TestCompareSignatures(t *testing.T) {
	message := sha256.Sum256([]byte("test message for MLDSA comparison"))
	t.Logf("Message (32 bytes): %x", message)

	// ============================================================
	// Part A: Generate key and sign with cloudflare/circl
	// ============================================================
	t.Log("\n=== CLOUDFLARE/CIRCL (what the node uses) ===")

	circlScheme := mldsa44.Scheme()

	// Generate key using the cosmos-sdk MLDSA code path (same as node)
	scheme44 := mldsa44.Scheme()
	var seed [mldsa44.SeedSize]byte
	_, err := rand.Read(seed[:])
	require.NoError(t, err)

	circlPubKey, circlPrivKey := mldsa44.NewKeyFromSeed(&seed)
	circlPubBytes := circlPubKey.Bytes()

	// Sign using the scheme (same way cosmos-sdk does it)
	circlSig := scheme44.Sign(circlPrivKey, message[:], nil)

	t.Logf("circl pubkey:    %d bytes, first16=%x", len(circlPubBytes), circlPubBytes[:16])
	t.Logf("circl signature: %d bytes, first16=%x", len(circlSig), circlSig[:16])

	// Verify circl sig with circl
	circlPubParsed, err := circlScheme.UnmarshalBinaryPublicKey(circlPubBytes)
	require.NoError(t, err)
	circlSelfVerify := circlScheme.Verify(circlPubParsed, message[:], circlSig, nil)
	t.Logf("circl verify(circl sig): %v", circlSelfVerify)

	// ============================================================
	// Part B: Generate key and sign with vscore (go-wrappers)
	// ============================================================
	t.Log("\n=== VSCORE/GO-WRAPPERS (what the TSS uses) ===")

	shares := doKeygen(t, mldsaSession.MlDsa44, 2, 2)
	require.Len(t, shares, 2)

	vscorePubBytes, err := mldsaSession.MldsaKeysharePublicKey(shares[0])
	require.NoError(t, err)

	var vscoreSig []byte
	for attempt := 0; attempt < 30; attempt++ {
		if attempt > 0 {
			shares = doKeygen(t, mldsaSession.MlDsa44, 2, 2)
			vscorePubBytes, _ = mldsaSession.MldsaKeysharePublicKey(shares[0])
		}
		vscoreSig = doSign(t, mldsaSession.MlDsa44, shares, message[:])
		if vscoreSig != nil {
			t.Logf("vscore signing succeeded on attempt %d", attempt)
			break
		}
	}
	require.NotNil(t, vscoreSig, "vscore signing should succeed")

	t.Logf("vscore pubkey:    %d bytes, first16=%x", len(vscorePubBytes), vscorePubBytes[:16])
	t.Logf("vscore signature: %d bytes, first16=%x", len(vscoreSig), vscoreSig[:16])

	// ============================================================
	// Part C: Cross-verification matrix
	// ============================================================
	t.Log("\n=== CROSS-VERIFICATION MATRIX ===")

	// Parse vscore pubkey with circl
	vscorePubParsed, err := circlScheme.UnmarshalBinaryPublicKey(vscorePubBytes)
	require.NoError(t, err, "circl should parse vscore pubkey")

	// All combinations
	t.Log("\nVerifying with circl verifier:")
	t.Logf("  circl_verify(circl_pub,  circl_sig,  msg)  = %v", circlScheme.Verify(circlPubParsed, message[:], circlSig, nil))
	t.Logf("  circl_verify(vscore_pub, vscore_sig, msg)  = %v", circlScheme.Verify(vscorePubParsed, message[:], vscoreSig, nil))
	t.Logf("  circl_verify(circl_pub,  vscore_sig, msg)  = %v", circlScheme.Verify(circlPubParsed, message[:], vscoreSig, nil))
	t.Logf("  circl_verify(vscore_pub, circl_sig,  msg)  = %v", circlScheme.Verify(vscorePubParsed, message[:], circlSig, nil))

	// ============================================================
	// Part D: Hex dump for comparison
	// ============================================================
	t.Log("\n=== FULL HEX DUMPS ===")
	t.Logf("\ncircl pubkey (%d bytes):\n%s", len(circlPubBytes), hex.EncodeToString(circlPubBytes))
	t.Logf("\nvscore pubkey (%d bytes):\n%s", len(vscorePubBytes), hex.EncodeToString(vscorePubBytes))
	t.Logf("\ncircl signature (%d bytes):\n%s", len(circlSig), hex.EncodeToString(circlSig))
	t.Logf("\nvscore signature (%d bytes):\n%s", len(vscoreSig), hex.EncodeToString(vscoreSig))

	// ============================================================
	// Part E: Structural comparison
	// ============================================================
	t.Log("\n=== STRUCTURAL ANALYSIS ===")

	// Check if first bytes differ (could indicate different encoding/format)
	if len(circlSig) == len(vscoreSig) {
		diffCount := 0
		firstDiff := -1
		for i := range circlSig {
			if circlSig[i] != vscoreSig[i] {
				diffCount++
				if firstDiff == -1 {
					firstDiff = i
				}
			}
		}
		t.Logf("Signature size: both %d bytes", len(circlSig))
		t.Logf("Differing bytes: %d / %d (%.1f%%)", diffCount, len(circlSig), float64(diffCount)*100/float64(len(circlSig)))
		if firstDiff >= 0 {
			t.Logf("First difference at byte %d: circl=0x%02x vscore=0x%02x", firstDiff, circlSig[firstDiff], vscoreSig[firstDiff])
		}
	}

	// Check if signatures are byte-reversed or have simple transformations
	if len(circlSig) == len(vscoreSig) {
		// Check if vscore sig reversed equals circl sig
		reversed := make([]byte, len(vscoreSig))
		for i, b := range vscoreSig {
			reversed[len(vscoreSig)-1-i] = b
		}
		if string(reversed) == string(circlSig) {
			t.Log("NOTE: vscore signature is byte-reversed circl signature!")
		}
	}

	// Summary
	t.Log("\n=== SUMMARY ===")
	fmt.Println()
	fmt.Println("Cross-verification matrix:")
	fmt.Println("                    | circl verifier")
	fmt.Println("  circl_pub + circl_sig  =", circlScheme.Verify(circlPubParsed, message[:], circlSig, nil))
	fmt.Println("  vscore_pub + vscore_sig =", circlScheme.Verify(vscorePubParsed, message[:], vscoreSig, nil))
	fmt.Println("  circl_pub + vscore_sig  =", circlScheme.Verify(circlPubParsed, message[:], vscoreSig, nil))
	fmt.Println("  vscore_pub + circl_sig  =", circlScheme.Verify(vscorePubParsed, message[:], circlSig, nil))
}
