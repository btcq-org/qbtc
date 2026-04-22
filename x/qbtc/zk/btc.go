package zk

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
)

// PubKeyHashSHA256 returns SHA256 of the 33-byte SEC-compressed public key.
// This is the public input to the ZK circuit that commits to the pubkey; the
// verifier additionally applies RIPEMD160 natively to recover the Hash160
// Bitcoin AddressHash.
func PubKeyHashSHA256(compressedPubKey []byte) ([32]byte, error) {
	var result [32]byte
	if len(compressedPubKey) != 33 {
		return result, fmt.Errorf("invalid compressed public key length: %d", len(compressedPubKey))
	}
	return sha256.Sum256(compressedPubKey), nil
}

// PrivateKeyToAddressHash computes the Bitcoin address hash (Hash160) from a private key.
// Returns an error if the private key is not in the valid range [1, n-1].
func PrivateKeyToAddressHash(privateKey *btcec.PrivateKey) ([20]byte, error) {
	return PublicKeyToAddressHash(privateKey.PubKey().SerializeCompressed())
}

// PublicKeyToAddressHash computes the Bitcoin address hash from a compressed public key
func PublicKeyToAddressHash(compressedPubKey []byte) ([20]byte, error) {
	var result [20]byte

	if len(compressedPubKey) != 33 {
		return result, fmt.Errorf("invalid compressed public key length: %d", len(compressedPubKey))
	}

	addrPubKey, err := btcutil.NewAddressPubKey(compressedPubKey, &chaincfg.MainNetParams)
	if err != nil {
		return result, fmt.Errorf("failed to create address from public key: %w", err)
	}
	addrPubKeyHash := addrPubKey.AddressPubKeyHash()
	copy(result[:], addrPubKeyHash.Hash160()[:])
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

// Hash160ToP2PKHAddress converts a Hash160 to a P2PKH Bitcoin address (mainnet)
func Hash160ToP2PKHAddress(hash [20]byte) (string, error) {
	addr, err := btcutil.NewAddressPubKeyHash(hash[:], &chaincfg.MainNetParams)
	if err != nil {
		return "", fmt.Errorf("failed to create address: %w", err)
	}
	return addr.EncodeAddress(), nil
}

// BitcoinAddressToHash160 extracts the Hash160 from P2PKH or P2WPKH Bitcoin addresses.
// Other address types (P2SH, P2TR, P2WSH, P2PK) are not supported.
func BitcoinAddressToHash160(address string) ([20]byte, error) {
	var result [20]byte
	// only do mainnet
	addr, err := btcutil.DecodeAddress(address, &chaincfg.MainNetParams)
	if err != nil {
		return result, fmt.Errorf("invalid Bitcoin address: %w", err)
	}
	switch a := addr.(type) {
	case *btcutil.AddressPubKeyHash:
		copy(result[:], a.Hash160()[:])
		return result, nil
	case *btcutil.AddressWitnessPubKeyHash:
		copy(result[:], a.Hash160()[:])
		return result, nil
	default:
		return result, fmt.Errorf("unsupported address type")
	}
}
