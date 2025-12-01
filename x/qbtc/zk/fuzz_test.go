package zk

import (
	"testing"
)

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
		_, err := BitcoinAddressToHash160(address)
		if err != nil {
			return
		}
	})
}

// FuzzAddressHashFromHex tests address hash hex parsing.
func FuzzAddressHashFromHex(f *testing.F) {
	// Add seed corpus
	f.Add("")
	f.Add("00")
	f.Add("0000000000000000000000000000000000000001")  // Valid
	f.Add("000000000000000000000000000000000000000")   // 19 bytes
	f.Add("00000000000000000000000000000000000000001") // 21 bytes
	f.Add("gg")                                        // Invalid hex

	f.Fuzz(func(t *testing.T, hexStr string) {
		// Should never panic
		_, err := AddressHashFromHex(hexStr)
		if err != nil {
			// If error, just return
			return
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
