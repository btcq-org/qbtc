package zk

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math/big"

	"github.com/btcsuite/btcd/btcec/v2"
	"golang.org/x/crypto/ripemd160"
)

// secp256k1Order is the order of the secp256k1 curve (n).
// Private keys must be in the range [1, n-1].
var secp256k1Order = func() *big.Int {
	n, _ := new(big.Int).SetString("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16)
	return n
}()

// Hash160 computes RIPEMD160(SHA256(data))
func Hash160(data []byte) []byte {
	sha := sha256.Sum256(data)
	ripemd := ripemd160.New()
	ripemd.Write(sha[:])
	return ripemd.Sum(nil)
}

// ValidatePrivateKey checks if a private key is in the valid range for secp256k1.
// Valid range is [1, n-1] where n is the curve order.
func ValidatePrivateKey(privateKey *big.Int) error {
	if privateKey == nil {
		return fmt.Errorf("private key is nil")
	}
	if privateKey.Sign() <= 0 {
		return fmt.Errorf("private key must be positive")
	}
	if privateKey.Cmp(secp256k1Order) >= 0 {
		return fmt.Errorf("private key must be less than curve order")
	}
	return nil
}

// PrivateKeyToAddressHash computes the Bitcoin address hash (Hash160) from a private key.
// Returns an error if the private key is not in the valid range [1, n-1].
func PrivateKeyToAddressHash(privateKey *big.Int) ([20]byte, error) {
	var result [20]byte

	// Validate private key range
	if err := ValidatePrivateKey(privateKey); err != nil {
		return result, fmt.Errorf("invalid private key: %w", err)
	}

	// Create the private key on secp256k1
	// Pad to 32 bytes to ensure correct handling
	pkBytes := make([]byte, 32)
	privateKey.FillBytes(pkBytes)
	privKey, _ := btcec.PrivKeyFromBytes(pkBytes)

	// Verify the key wasn't modified (sanity check)
	reconstructed := new(big.Int).SetBytes(privKey.Serialize())
	if reconstructed.Cmp(privateKey) != 0 {
		return result, fmt.Errorf("private key was modified during parsing (got %s, expected %s)",
			reconstructed.Text(16), privateKey.Text(16))
	}

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

// Hash160ToP2PKHAddress converts a Hash160 to a P2PKH Bitcoin address (mainnet)
func Hash160ToP2PKHAddress(hash [20]byte) string {
	// P2PKH mainnet version byte is 0x00
	versionedPayload := make([]byte, 21)
	versionedPayload[0] = 0x00
	copy(versionedPayload[1:], hash[:])

	// Compute checksum (first 4 bytes of double SHA256)
	checksum := doubleSHA256(versionedPayload)[:4]

	// Concatenate payload + checksum
	fullPayload := append(versionedPayload, checksum...)

	// Base58 encode
	return base58Encode(fullPayload)
}

// base58Encode encodes bytes to base58
func base58Encode(input []byte) string {
	alphabet := "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

	// Count leading zeros
	leadingZeros := 0
	for _, b := range input {
		if b == 0 {
			leadingZeros++
		} else {
			break
		}
	}

	// Convert to big integer
	num := new(big.Int).SetBytes(input)
	base := big.NewInt(58)
	zero := big.NewInt(0)
	mod := new(big.Int)

	var result []byte
	for num.Cmp(zero) > 0 {
		num.DivMod(num, base, mod)
		result = append([]byte{alphabet[mod.Int64()]}, result...)
	}

	// Add leading '1's for leading zero bytes
	for i := 0; i < leadingZeros; i++ {
		result = append([]byte{'1'}, result...)
	}

	return string(result)
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
		if len(decoded) < 25 {
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

// bech32Decode decodes a bech32 address with proper checksum validation.
func bech32Decode(address string) (string, []byte, error) {
	// Convert to lowercase for processing
	address = toLowerASCII(address)

	// Find the separator (last occurrence of '1')
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
	if sepIdx < 1 {
		return "", nil, fmt.Errorf("HRP too short")
	}
	if len(address)-sepIdx-1 < 6 {
		return "", nil, fmt.Errorf("data part too short")
	}

	hrp := address[:sepIdx]
	dataPart := address[sepIdx+1:]

	// Decode the data part
	charset := "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
	data := make([]byte, 0, len(dataPart))
	for _, c := range dataPart {
		idx := -1
		for i, ch := range charset {
			if ch == rune(c) {
				idx = i
				break
			}
		}
		if idx == -1 {
			return "", nil, fmt.Errorf("invalid character in data part: %c", c)
		}
		data = append(data, byte(idx))
	}

	// Verify checksum
	if !bech32VerifyChecksum(hrp, data) {
		return "", nil, fmt.Errorf("invalid bech32 checksum")
	}

	// Skip version byte and convert from 5-bit to 8-bit
	if len(data) < 7 {
		return "", nil, fmt.Errorf("data too short")
	}

	// First byte is version, last 6 bytes are checksum
	data5bit := data[1 : len(data)-6]

	// Convert 5-bit to 8-bit
	result := convert5to8(data5bit)

	return hrp, result, nil
}

// toLowerASCII converts ASCII uppercase to lowercase
func toLowerASCII(s string) string {
	b := []byte(s)
	for i, c := range b {
		if c >= 'A' && c <= 'Z' {
			b[i] = c + 32
		}
	}
	return string(b)
}

// bech32Polymod computes the bech32 checksum polynomial
func bech32Polymod(values []byte) uint32 {
	gen := []uint32{0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3}
	chk := uint32(1)
	for _, v := range values {
		top := chk >> 25
		chk = (chk&0x1ffffff)<<5 ^ uint32(v)
		for i := 0; i < 5; i++ {
			if (top>>i)&1 == 1 {
				chk ^= gen[i]
			}
		}
	}
	return chk
}

// bech32HRPExpand expands the HRP for checksum computation
func bech32HRPExpand(hrp string) []byte {
	result := make([]byte, len(hrp)*2+1)
	for i, c := range hrp {
		result[i] = byte(c >> 5)
	}
	result[len(hrp)] = 0
	for i, c := range hrp {
		result[len(hrp)+1+i] = byte(c & 31)
	}
	return result
}

// bech32VerifyChecksum verifies the bech32 checksum
func bech32VerifyChecksum(hrp string, data []byte) bool {
	values := append(bech32HRPExpand(hrp), data...)
	return bech32Polymod(values) == 1
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
