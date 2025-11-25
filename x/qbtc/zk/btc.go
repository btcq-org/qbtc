package zk

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math/big"

	"github.com/btcsuite/btcd/btcec/v2"
	"golang.org/x/crypto/ripemd160"
)

// Hash160 computes RIPEMD160(SHA256(data))
func Hash160(data []byte) []byte {
	sha := sha256.Sum256(data)
	ripemd := ripemd160.New()
	ripemd.Write(sha[:])
	return ripemd.Sum(nil)
}

// PrivateKeyToAddressHash computes the Bitcoin address hash (Hash160) from a private key
func PrivateKeyToAddressHash(privateKey *big.Int) ([20]byte, error) {
	var result [20]byte

	// Create the private key on secp256k1
	privKey, _ := btcec.PrivKeyFromBytes(privateKey.Bytes())

	// Get the compressed public key (33 bytes)
	compressedPubKey := privKey.PubKey().SerializeCompressed()

	// Compute Hash160
	hash := Hash160(compressedPubKey)
	if len(hash) != 20 {
		return result, fmt.Errorf("unexpected hash length: %d", len(hash))
	}
	copy(result[:], hash)

	return result, nil
}

// PublicKeyToAddressHash computes the Bitcoin address hash from a compressed public key
func PublicKeyToAddressHash(compressedPubKey []byte) ([20]byte, error) {
	var result [20]byte

	if len(compressedPubKey) != 33 {
		return result, fmt.Errorf("invalid compressed public key length: %d", len(compressedPubKey))
	}

	hash := Hash160(compressedPubKey)
	copy(result[:], hash)

	return result, nil
}

// AddressHashFromHex parses a hex-encoded address hash
func AddressHashFromHex(hexStr string) ([20]byte, error) {
	var result [20]byte

	decoded, err := hex.DecodeString(hexStr)
	if err != nil {
		return result, fmt.Errorf("invalid hex: %w", err)
	}

	if len(decoded) != 20 {
		return result, fmt.Errorf("invalid address hash length: %d", len(decoded))
	}

	copy(result[:], decoded)
	return result, nil
}

// AddressHashToHex converts an address hash to hex string
func AddressHashToHex(hash [20]byte) string {
	return hex.EncodeToString(hash[:])
}

// PrivateKeyFromHex parses a hex-encoded private key
func PrivateKeyFromHex(hexStr string) (*big.Int, error) {
	decoded, err := hex.DecodeString(hexStr)
	if err != nil {
		return nil, fmt.Errorf("invalid hex: %w", err)
	}

	return new(big.Int).SetBytes(decoded), nil
}

// PrivateKeyFromWIF parses a WIF-encoded private key
// WIF format: Base58Check(version + privateKey + [compressed flag])
func PrivateKeyFromWIF(wif string) (*big.Int, error) {
	// Decode base58check
	decoded := base58Decode(wif)
	if decoded == nil {
		return nil, fmt.Errorf("invalid base58 encoding")
	}

	// Verify checksum
	if len(decoded) < 5 {
		return nil, fmt.Errorf("WIF too short")
	}
	payload := decoded[:len(decoded)-4]
	checksum := decoded[len(decoded)-4:]
	expectedChecksum := doubleSHA256(payload)[:4]

	for i := 0; i < 4; i++ {
		if checksum[i] != expectedChecksum[i] {
			return nil, fmt.Errorf("invalid checksum")
		}
	}

	// Extract private key
	// Version byte is first, then 32 bytes of key
	// Optionally followed by 0x01 for compressed
	if len(payload) < 33 {
		return nil, fmt.Errorf("WIF payload too short")
	}

	privateKeyBytes := payload[1:33]
	return new(big.Int).SetBytes(privateKeyBytes), nil
}

// doubleSHA256 computes SHA256(SHA256(data))
func doubleSHA256(data []byte) []byte {
	first := sha256.Sum256(data)
	second := sha256.Sum256(first[:])
	return second[:]
}

// base58Decode decodes a base58 string
func base58Decode(input string) []byte {
	alphabet := "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
	result := big.NewInt(0)
	base := big.NewInt(58)

	for _, c := range input {
		charIndex := -1
		for i, a := range alphabet {
			if a == c {
				charIndex = i
				break
			}
		}
		if charIndex == -1 {
			return nil
		}

		result.Mul(result, base)
		result.Add(result, big.NewInt(int64(charIndex)))
	}

	// Count leading '1's for leading zeros
	leadingZeros := 0
	for _, c := range input {
		if c == '1' {
			leadingZeros++
		} else {
			break
		}
	}

	resultBytes := result.Bytes()
	return append(make([]byte, leadingZeros), resultBytes...)
}

// ValidateAddressHash checks if an address hash is valid
func ValidateAddressHash(hash []byte) error {
	if len(hash) != 20 {
		return fmt.Errorf("invalid address hash length: expected 20 bytes, got %d", len(hash))
	}
	return nil
}

// BitcoinAddressToHash160 extracts the Hash160 from various Bitcoin address formats
// Supports: P2PKH (1...), P2WPKH (bc1q...), P2SH-P2WPKH (3...)
func BitcoinAddressToHash160(address string) ([20]byte, error) {
	var result [20]byte

	// Detect address type by prefix
	switch {
	case len(address) > 0 && address[0] == '1':
		// P2PKH address - decode base58check and extract hash160
		decoded := base58Decode(address)
		if decoded == nil || len(decoded) < 25 {
			return result, fmt.Errorf("invalid P2PKH address")
		}
		// Skip version byte, take next 20 bytes
		copy(result[:], decoded[1:21])

	case len(address) > 4 && address[:4] == "bc1q":
		// P2WPKH (native SegWit) - decode bech32
		_, data, err := bech32Decode(address)
		if err != nil {
			return result, fmt.Errorf("invalid bech32 address: %w", err)
		}
		if len(data) < 20 {
			return result, fmt.Errorf("invalid witness program length")
		}
		copy(result[:], data[:20])

	case len(address) > 0 && address[0] == '3':
		// P2SH-P2WPKH - this contains Hash160(redeemScript), not the pubkey hash
		// We can't directly extract the pubkey hash from this
		return result, fmt.Errorf("P2SH-P2WPKH addresses require the redeemScript to extract pubkey hash")

	default:
		return result, fmt.Errorf("unsupported address format")
	}

	return result, nil
}

// bech32Decode decodes a bech32 address (simplified implementation)
func bech32Decode(address string) (string, []byte, error) {
	// Find the separator
	sepIdx := -1
	for i := len(address) - 1; i >= 0; i-- {
		if address[i] == '1' {
			sepIdx = i
			break
		}
	}
	if sepIdx == -1 {
		return "", nil, fmt.Errorf("no separator found")
	}

	hrp := address[:sepIdx]
	dataPart := address[sepIdx+1:]

	// Decode the data part
	charset := "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
	data := make([]byte, 0, len(dataPart))
	for _, c := range dataPart {
		idx := -1
		for i, ch := range charset {
			if ch == c {
				idx = i
				break
			}
		}
		if idx == -1 {
			return "", nil, fmt.Errorf("invalid character in data part")
		}
		data = append(data, byte(idx))
	}

	// Skip version byte and convert from 5-bit to 8-bit
	if len(data) < 7 {
		return "", nil, fmt.Errorf("data too short")
	}

	// First byte is version, skip it
	// Last 6 bytes are checksum, skip them
	data5bit := data[1 : len(data)-6]

	// Convert 5-bit to 8-bit
	result := convert5to8(data5bit)

	return hrp, result, nil
}

// convert5to8 converts 5-bit encoding to 8-bit bytes
func convert5to8(data []byte) []byte {
	var result []byte
	acc := 0
	bits := 0

	for _, d := range data {
		acc = (acc << 5) | int(d)
		bits += 5
		for bits >= 8 {
			bits -= 8
			result = append(result, byte((acc>>bits)&0xFF))
		}
	}

	return result
}
