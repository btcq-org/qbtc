//go:build testing

package zk

import (
	"crypto/sha256"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestAddressTypeDetection tests the address type detection function
func TestAddressTypeDetection(t *testing.T) {
	tests := []struct {
		name     string
		address  string
		expected AddressType
	}{
		{"P2PKH mainnet", "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2", AddressTypeP2PKH},
		{"P2WPKH mainnet", "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq", AddressTypeP2WPKH},
		{"P2SH mainnet", "3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy", AddressTypeP2SH},
		{"P2TR mainnet", "bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0", AddressTypeP2TR},
		{"Invalid address", "invalid", AddressTypeUnknown},
		{"Empty address", "", AddressTypeUnknown},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := DetectAddressType(tt.address)
			require.Equal(t, tt.expected, result, "address type mismatch for %s", tt.address)
		})
	}
}

// TestCircuitTypeForAddressType tests the mapping from address type to circuit type
func TestCircuitTypeForAddressType(t *testing.T) {
	tests := []struct {
		addrType    AddressType
		circuitType CircuitType
		shouldError bool
	}{
		{AddressTypeP2PKH, CircuitTypeECDSA, false},
		{AddressTypeP2WPKH, CircuitTypeECDSA, false},
		{AddressTypeP2SH, CircuitTypeP2SHP2WPKH, false},
		{AddressTypeP2TR, CircuitTypeSchnorr, false},
		{AddressTypeP2PK, CircuitTypeP2PK, false},
		{AddressTypeUnknown, CircuitTypeECDSA, true},
	}

	for _, tt := range tests {
		t.Run(tt.addrType.String(), func(t *testing.T) {
			ct, err := CircuitTypeForAddressType(tt.addrType)
			if tt.shouldError {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				require.Equal(t, tt.circuitType, ct)
			}
		})
	}
}

// TestTaprootAddressParsing tests Taproot address parsing and conversion
func TestTaprootAddressParsing(t *testing.T) {
	// Valid Taproot address (from BIP-350 test vectors)
	taprootAddr := "bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0"

	t.Run("extract x-only pubkey from taproot address", func(t *testing.T) {
		xOnlyPubKey, err := TaprootAddressToXOnlyPubKey(taprootAddr)
		require.NoError(t, err)
		require.Len(t, xOnlyPubKey, 32)

		// Convert back to address
		addr, err := XOnlyPubKeyToTaprootAddress(xOnlyPubKey)
		require.NoError(t, err)
		require.Equal(t, taprootAddr, addr)
	})

	t.Run("reject non-taproot address", func(t *testing.T) {
		_, err := TaprootAddressToXOnlyPubKey("bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq")
		require.Error(t, err)
		require.Contains(t, err.Error(), "not a Taproot address")
	})
}

// TestP2SHP2WPKHScriptHashComputation tests the P2SH-P2WPKH script hash computation
func TestP2SHP2WPKHScriptHashComputation(t *testing.T) {
	// Use a known pubkey hash
	pubkeyHash160 := [20]byte{
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
		0x10, 0x11, 0x12, 0x13,
	}

	t.Run("compute script hash", func(t *testing.T) {
		scriptHash := ComputeP2SHP2WPKHScriptHash(pubkeyHash160)
		require.Len(t, scriptHash, 20)

		// Verify it's different from the input
		require.NotEqual(t, pubkeyHash160, scriptHash)
	})

	t.Run("script hash is deterministic", func(t *testing.T) {
		hash1 := ComputeP2SHP2WPKHScriptHash(pubkeyHash160)
		hash2 := ComputeP2SHP2WPKHScriptHash(pubkeyHash160)
		require.Equal(t, hash1, hash2)
	})

	t.Run("different pubkey hash produces different script hash", func(t *testing.T) {
		otherPubkeyHash := pubkeyHash160
		otherPubkeyHash[0] = 0xFF

		hash1 := ComputeP2SHP2WPKHScriptHash(pubkeyHash160)
		hash2 := ComputeP2SHP2WPKHScriptHash(otherPubkeyHash)
		require.NotEqual(t, hash1, hash2)
	})
}

// TestTaggedHash tests the BIP-340 tagged hash implementation
func TestTaggedHash(t *testing.T) {
	t.Run("tagged hash is deterministic", func(t *testing.T) {
		data := []byte("test data")
		hash1 := TaggedHash(TagBIP340Challenge, data)
		hash2 := TaggedHash(TagBIP340Challenge, data)
		require.Equal(t, hash1, hash2)
	})

	t.Run("different tags produce different hashes", func(t *testing.T) {
		data := []byte("test data")
		hash1 := TaggedHash(TagBIP340Challenge, data)
		hash2 := TaggedHash(TagTapTweak, data)
		require.NotEqual(t, hash1, hash2)
	})

	t.Run("different data produces different hashes", func(t *testing.T) {
		hash1 := TaggedHash(TagBIP340Challenge, []byte("data1"))
		hash2 := TaggedHash(TagBIP340Challenge, []byte("data2"))
		require.NotEqual(t, hash1, hash2)
	})

	t.Run("precomputed tag hash matches", func(t *testing.T) {
		expectedTagHash := sha256.Sum256([]byte(TagBIP340Challenge))
		require.Equal(t, expectedTagHash, TagHashBIP340Challenge)
	})

	t.Run("tagged hash with precomputed matches regular", func(t *testing.T) {
		data := []byte("test data")
		hash1 := TaggedHash(TagBIP340Challenge, data)
		hash2 := TaggedHashWithPrecomputedTag(TagHashBIP340Challenge, data)
		require.Equal(t, hash1, hash2)
	})
}

// TestClaimMessageFormats tests the claim message computation for different address types
func TestClaimMessageFormats(t *testing.T) {
	btcqAddressHash := HashBTCQAddress("qbtc1test")
	chainIDHash := ComputeChainIDHash("qbtc-1")

	t.Run("ECDSA claim message (P2PKH/P2WPKH)", func(t *testing.T) {
		addressHash := [20]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20}
		msg := ComputeClaimMessage(addressHash, btcqAddressHash, chainIDHash)
		require.Len(t, msg, 32)

		// Verify determinism
		msg2 := ComputeClaimMessage(addressHash, btcqAddressHash, chainIDHash)
		require.Equal(t, msg, msg2)
	})

	t.Run("Schnorr claim message (Taproot)", func(t *testing.T) {
		xOnlyPubKey := [32]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
			17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32}
		msg := ComputeClaimMessageForSchnorr(xOnlyPubKey, btcqAddressHash, chainIDHash)
		require.Len(t, msg, 32)

		// Verify it's different from ECDSA format (different identifier size)
		addressHash := [20]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20}
		ecdsaMsg := ComputeClaimMessage(addressHash, btcqAddressHash, chainIDHash)
		require.NotEqual(t, msg, ecdsaMsg)
	})

	t.Run("P2SH claim message", func(t *testing.T) {
		scriptHash := [20]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20}
		msg := ComputeClaimMessageForP2SH(scriptHash, btcqAddressHash, chainIDHash)
		require.Len(t, msg, 32)

		// Same size as ECDSA but should be different due to different script hash
		addressHash := [20]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20}
		ecdsaMsg := ComputeClaimMessage(addressHash, btcqAddressHash, chainIDHash)
		// These happen to be the same since we use the same 20-byte input
		require.Equal(t, msg, ecdsaMsg)
	})

	t.Run("P2PK claim message", func(t *testing.T) {
		compressedPubKey := [33]byte{0x02, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
			17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32}
		msg := ComputeClaimMessageForP2PK(compressedPubKey, btcqAddressHash, chainIDHash)
		require.Len(t, msg, 32)

		// Different from Schnorr (33 vs 32 bytes identifier)
		xOnlyPubKey := [32]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
			17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32}
		schnorrMsg := ComputeClaimMessageForSchnorr(xOnlyPubKey, btcqAddressHash, chainIDHash)
		require.NotEqual(t, msg, schnorrMsg)
	})
}

// TestMultiVerifierRegistration tests the multi-verifier registration
func TestMultiVerifierRegistration(t *testing.T) {
	mv := NewMultiVerifier()

	t.Run("initially no circuits registered", func(t *testing.T) {
		require.False(t, mv.HasCircuit(CircuitTypeECDSA))
		require.False(t, mv.HasCircuit(CircuitTypeSchnorr))
		require.False(t, mv.HasCircuit(CircuitTypeP2SHP2WPKH))
		require.False(t, mv.HasCircuit(CircuitTypeP2PK))
	})

	t.Run("verify fails for unregistered circuit", func(t *testing.T) {
		err := mv.VerifyECDSAProof(nil, VerificationParams{})
		require.Error(t, err)
		require.Contains(t, err.Error(), "not registered")
	})
}

// TestProofSerialization tests the Proof serialization round-trip
func TestProofSerialization(t *testing.T) {
	original := &Proof{
		ProofData: []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
			17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32,
			33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48,
			49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64,
			65, 66, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 77, 78, 79, 80,
			81, 82, 83, 84, 85, 86, 87, 88, 89, 90, 91, 92, 93, 94, 95, 96,
			97, 98, 99, 100},
		PublicInputs: []byte{200, 201, 202, 203, 204, 205},
	}

	t.Run("round-trip serialization", func(t *testing.T) {
		serialized := original.ToProtoZKProof()
		require.NotEmpty(t, serialized)

		deserialized, err := ProofFromProtoZKProof(serialized)
		require.NoError(t, err)
		require.Equal(t, original.ProofData, deserialized.ProofData)
		require.Equal(t, original.PublicInputs, deserialized.PublicInputs)
	})

	t.Run("reject too short data", func(t *testing.T) {
		_, err := ProofFromProtoZKProof([]byte{1, 2, 3})
		require.Error(t, err)
	})

	t.Run("reject invalid proof length", func(t *testing.T) {
		// Create data with length field indicating 50 bytes (below minimum)
		data := []byte{0, 0, 0, 50}
		data = append(data, make([]byte, 50)...)
		_, err := ProofFromProtoZKProof(data)
		require.Error(t, err)
		require.Contains(t, err.Error(), "invalid proof length")
	})
}

// TestP2WSHSingleKeyWitnessProgram tests the P2WSH single-key witness program computation
func TestP2WSHSingleKeyWitnessProgram(t *testing.T) {
	// Create a test compressed public key
	compressedPubKey := [33]byte{
		0x02, // Even Y prefix
		0x79, 0xBE, 0x66, 0x7E, 0xF9, 0xDC, 0xBB, 0xAC,
		0x55, 0xA0, 0x62, 0x95, 0xCE, 0x87, 0x0B, 0x07,
		0x02, 0x9B, 0xFC, 0xDB, 0x2D, 0xCE, 0x28, 0xD9,
		0x59, 0xF2, 0x81, 0x5B, 0x16, 0xF8, 0x17, 0x98,
	}

	t.Run("compute witness program", func(t *testing.T) {
		witnessProgram := ComputeP2WSHSingleKeyWitnessProgram(compressedPubKey)
		require.Len(t, witnessProgram, 32)

		// Verify it's not all zeros
		allZeros := true
		for _, b := range witnessProgram {
			if b != 0 {
				allZeros = false
				break
			}
		}
		require.False(t, allZeros, "witness program should not be all zeros")
	})

	t.Run("witness program is deterministic", func(t *testing.T) {
		wp1 := ComputeP2WSHSingleKeyWitnessProgram(compressedPubKey)
		wp2 := ComputeP2WSHSingleKeyWitnessProgram(compressedPubKey)
		require.Equal(t, wp1, wp2)
	})

	t.Run("different pubkey produces different witness program", func(t *testing.T) {
		otherPubKey := compressedPubKey
		otherPubKey[1] = 0xFF

		wp1 := ComputeP2WSHSingleKeyWitnessProgram(compressedPubKey)
		wp2 := ComputeP2WSHSingleKeyWitnessProgram(otherPubKey)
		require.NotEqual(t, wp1, wp2)
	})

	t.Run("witness script format is correct", func(t *testing.T) {
		// The witness script should be: 0x21 || pubkey || 0xAC
		// SHA256 of this should equal the witness program
		witnessScript := make([]byte, 35)
		witnessScript[0] = 0x21 // OP_PUSHBYTES_33
		copy(witnessScript[1:34], compressedPubKey[:])
		witnessScript[34] = 0xAC // OP_CHECKSIG

		// Manually compute SHA256
		expected := sha256.Sum256(witnessScript)
		actual := ComputeP2WSHSingleKeyWitnessProgram(compressedPubKey)
		require.Equal(t, expected, actual)
	})
}

// TestP2WSHClaimMessage tests the P2WSH claim message computation
func TestP2WSHClaimMessage(t *testing.T) {
	witnessProgram := [32]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
		17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32}
	btcqAddressHash := HashBTCQAddress("qbtc1test")
	chainIDHash := ComputeChainIDHash("qbtc-1")

	t.Run("compute claim message", func(t *testing.T) {
		msg := ComputeClaimMessageForP2WSH(witnessProgram, btcqAddressHash, chainIDHash)
		require.Len(t, msg, 32)
	})

	t.Run("claim message is deterministic", func(t *testing.T) {
		msg1 := ComputeClaimMessageForP2WSH(witnessProgram, btcqAddressHash, chainIDHash)
		msg2 := ComputeClaimMessageForP2WSH(witnessProgram, btcqAddressHash, chainIDHash)
		require.Equal(t, msg1, msg2)
	})

	t.Run("different witness program produces different message", func(t *testing.T) {
		otherWP := witnessProgram
		otherWP[0] = 0xFF

		msg1 := ComputeClaimMessageForP2WSH(witnessProgram, btcqAddressHash, chainIDHash)
		msg2 := ComputeClaimMessageForP2WSH(otherWP, btcqAddressHash, chainIDHash)
		require.NotEqual(t, msg1, msg2)
	})
}

// TestLiftXToPoint tests the x-only pubkey to full point conversion
func TestLiftXToPoint(t *testing.T) {
	// Use a known valid x-coordinate
	// This is a randomly generated valid point's x-coordinate
	xOnly := [32]byte{
		0x79, 0xBE, 0x66, 0x7E, 0xF9, 0xDC, 0xBB, 0xAC,
		0x55, 0xA0, 0x62, 0x95, 0xCE, 0x87, 0x0B, 0x07,
		0x02, 0x9B, 0xFC, 0xDB, 0x2D, 0xCE, 0x28, 0xD9,
		0x59, 0xF2, 0x81, 0x5B, 0x16, 0xF8, 0x17, 0x98,
	}

	t.Run("lift x to point", func(t *testing.T) {
		pubKey, err := LiftXToPoint(xOnly)
		require.NoError(t, err)
		require.NotNil(t, pubKey)

		// Verify the x-coordinate matches
		serialized := pubKey.SerializeCompressed()
		require.Equal(t, xOnly[:], serialized[1:33])
	})
}
