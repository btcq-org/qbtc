//go:build testing

package zk

import (
	"bytes"
	"encoding/binary"
	"testing"
)

// FuzzProofFromProtoZKProof tests the proof parsing with random inputs.
// This helps catch edge cases in the deserialization logic.
func FuzzProofFromProtoZKProof(f *testing.F) {
	// Add seed corpus with interesting edge cases
	
	// Empty input
	f.Add([]byte{})
	
	// Too short (< 4 bytes for length header)
	f.Add([]byte{0x00})
	f.Add([]byte{0x00, 0x01})
	f.Add([]byte{0x00, 0x01, 0x02})
	
	// Valid length header but no data
	f.Add([]byte{0x00, 0x00, 0x00, 0x64}) // claims 100 bytes
	
	// Minimum valid proof size boundary
	minProof := make([]byte, 4+MinProofDataLen)
	binary.BigEndian.PutUint32(minProof[:4], uint32(MinProofDataLen))
	f.Add(minProof)
	
	// Just under minimum
	underMin := make([]byte, 4+MinProofDataLen-1)
	binary.BigEndian.PutUint32(underMin[:4], uint32(MinProofDataLen-1))
	f.Add(underMin)
	
	// Maximum proof size boundary
	maxHeader := make([]byte, 4)
	binary.BigEndian.PutUint32(maxHeader, uint32(MaxProofDataLen))
	f.Add(maxHeader)
	
	// Over maximum
	overMax := make([]byte, 4)
	binary.BigEndian.PutUint32(overMax, uint32(MaxProofDataLen+1))
	f.Add(overMax)
	
	// Integer overflow attempts
	f.Add([]byte{0xFF, 0xFF, 0xFF, 0xFF}) // max uint32
	f.Add([]byte{0x80, 0x00, 0x00, 0x00}) // 2^31
	
	// Valid-looking proof with public inputs
	validProof := make([]byte, 4+200+50) // 200 byte proof, 50 byte public inputs
	binary.BigEndian.PutUint32(validProof[:4], 200)
	for i := 4; i < len(validProof); i++ {
		validProof[i] = byte(i % 256)
	}
	f.Add(validProof)
	
	f.Fuzz(func(t *testing.T, data []byte) {
		// The function should never panic regardless of input
		proof, err := ProofFromProtoZKProof(data)
		
		// If parsing succeeds, verify invariants
		if err == nil {
			if proof == nil {
				t.Fatal("nil proof returned without error")
			}
			
			// ProofData should be within bounds
			if len(proof.ProofData) < MinProofDataLen {
				t.Fatalf("proof data below minimum: %d", len(proof.ProofData))
			}
			if len(proof.ProofData) > MaxProofDataLen {
				t.Fatalf("proof data above maximum: %d", len(proof.ProofData))
			}
			
			// Total parsed data should not exceed input
			if 4+len(proof.ProofData)+len(proof.PublicInputs) > len(data) {
				t.Fatal("parsed more data than input contained")
			}
		}
	})
}

// FuzzBitcoinAddressToHash160 tests Bitcoin address parsing with random inputs.
func FuzzBitcoinAddressToHash160(f *testing.F) {
	// Add seed corpus
	
	// Valid-looking P2PKH addresses
	f.Add("1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2")
	f.Add("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa") // Satoshi's address
	
	// Valid-looking P2WPKH addresses
	f.Add("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4")
	f.Add("bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq")
	
	// Invalid addresses
	f.Add("")
	f.Add("1")
	f.Add("bc1")
	f.Add("bc1q")
	f.Add("3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy") // P2SH (unsupported)
	f.Add("invalid-address")
	f.Add("1111111111111111111111111111111111") // Invalid checksum
	
	// Edge cases
	f.Add("bc1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq3ljey")
	
	f.Fuzz(func(t *testing.T, address string) {
		// Should never panic
		hash, err := BitcoinAddressToHash160(address)
		
		if err == nil {
			// If successful, hash must be exactly 20 bytes
			if len(hash) != 20 {
				t.Fatalf("unexpected hash length: %d", len(hash))
			}
		}
	})
}

// FuzzPrivateKeyFromHex tests hex private key parsing.
func FuzzPrivateKeyFromHex(f *testing.F) {
	// Add seed corpus
	f.Add("")
	f.Add("0")
	f.Add("1")
	f.Add("0000000000000000000000000000000000000000000000000000000000000001")
	f.Add("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364140") // n-1
	f.Add("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141") // n (invalid)
	f.Add("gg") // Invalid hex
	f.Add("not-hex")
	
	f.Fuzz(func(t *testing.T, hexStr string) {
		// Should never panic
		_, _ = PrivateKeyFromHex(hexStr)
	})
}

// FuzzPrivateKeyFromWIF tests WIF private key parsing.
func FuzzPrivateKeyFromWIF(f *testing.F) {
	// Add seed corpus
	f.Add("")
	f.Add("5")
	f.Add("K")
	f.Add("L")
	f.Add("invalid")
	f.Add("5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ") // Uncompressed
	f.Add("KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn") // Compressed
	
	f.Fuzz(func(t *testing.T, wif string) {
		// Should never panic
		_, _ = PrivateKeyFromWIF(wif)
	})
}

// FuzzAddressHashFromHex tests address hash hex parsing.
func FuzzAddressHashFromHex(f *testing.F) {
	// Add seed corpus
	f.Add("")
	f.Add("00")
	f.Add("0000000000000000000000000000000000000001") // 20 bytes = 40 hex chars
	f.Add("0000000000000000000000000000000000000001") // Valid
	f.Add("000000000000000000000000000000000000000") // 19 bytes
	f.Add("00000000000000000000000000000000000000001") // 21 bytes
	f.Add("gg") // Invalid hex
	
	f.Fuzz(func(t *testing.T, hexStr string) {
		// Should never panic
		hash, err := AddressHashFromHex(hexStr)
		
		if err == nil {
			// If successful, should be exactly 20 bytes
			if len(hash) != 20 {
				t.Fatalf("unexpected hash length: %d", len(hash))
			}
		}
	})
}

// FuzzDeserializeVerifyingKey tests VK deserialization with random inputs.
func FuzzDeserializeVerifyingKey(f *testing.F) {
	// Add seed corpus
	f.Add([]byte{})
	f.Add(make([]byte, 100))  // Min size, garbage
	f.Add(make([]byte, 1000)) // Larger garbage
	
	f.Fuzz(func(t *testing.T, data []byte) {
		// Should never panic
		_, _ = DeserializeVerifyingKey(data)
	})
}

// FuzzSerializationRoundTrip tests that serialized proofs can be deserialized.
func FuzzSerializationRoundTrip(f *testing.F) {
	// Create some valid proof-like structures
	validProof := make([]byte, 4+200)
	binary.BigEndian.PutUint32(validProof[:4], 200)
	for i := 4; i < len(validProof); i++ {
		validProof[i] = byte(i)
	}
	f.Add(validProof)
	
	f.Fuzz(func(t *testing.T, data []byte) {
		// Try to parse
		proof, err := ProofFromProtoZKProof(data)
		if err != nil {
			return // Invalid input, skip
		}
		
		// Re-serialize
		reserialized := proof.ToProtoZKProof()
		
		// Re-parse
		proof2, err := ProofFromProtoZKProof(reserialized)
		if err != nil {
			t.Fatalf("failed to reparse serialized proof: %v", err)
		}
		
		// Should be equivalent
		if !bytes.Equal(proof.ProofData, proof2.ProofData) {
			t.Fatal("proof data mismatch after round trip")
		}
		if !bytes.Equal(proof.PublicInputs, proof2.PublicInputs) {
			t.Fatal("public inputs mismatch after round trip")
		}
	})
}

// FuzzBech32Decode tests bech32 address decoding with random inputs.
func FuzzBech32Decode(f *testing.F) {
	// Add seed corpus
	f.Add("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4")
	f.Add("BC1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KV8F3T4") // uppercase
	f.Add("bc1q")
	f.Add("")
	f.Add("tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx") // testnet
	
	f.Fuzz(func(t *testing.T, address string) {
		// Should never panic
		_, _, _ = bech32Decode(address)
	})
}

