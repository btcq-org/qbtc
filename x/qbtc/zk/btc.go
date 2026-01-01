package zk

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/txscript"
)

// AddressType represents the type of Bitcoin address/script
type AddressType int

const (
	// AddressTypeUnknown is an unknown or unsupported address type
	AddressTypeUnknown AddressType = iota
	// AddressTypeP2PKH is Pay-to-Public-Key-Hash (addresses starting with "1")
	AddressTypeP2PKH
	// AddressTypeP2WPKH is Pay-to-Witness-Public-Key-Hash (native SegWit, "bc1q...")
	AddressTypeP2WPKH
	// AddressTypeP2SH is Pay-to-Script-Hash (addresses starting with "3")
	AddressTypeP2SH
	// AddressTypeP2TR is Pay-to-Taproot (SegWit v1, "bc1p...")
	AddressTypeP2TR
	// AddressTypeP2PK is Pay-to-Public-Key (legacy, raw pubkey in script)
	AddressTypeP2PK
	// AddressTypeP2WSH is Pay-to-Witness-Script-Hash (native SegWit for scripts)
	AddressTypeP2WSH
)

// String returns a human-readable name for the address type
func (t AddressType) String() string {
	switch t {
	case AddressTypeP2PKH:
		return "P2PKH"
	case AddressTypeP2WPKH:
		return "P2WPKH"
	case AddressTypeP2SH:
		return "P2SH"
	case AddressTypeP2TR:
		return "P2TR"
	case AddressTypeP2PK:
		return "P2PK"
	case AddressTypeP2WSH:
		return "P2WSH"
	default:
		return "Unknown"
	}
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

// BitcoinAddressToHash160 extracts the Hash160 from various Bitcoin address formats
// Supports: P2PKH (1...), P2WPKH (bc1q...), P2SH-P2WPKH (3...)
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
	case *btcutil.AddressScriptHash:
		// P2SH address contains Hash160(redeemScript), not pubkey hash
		return result, fmt.Errorf("P2SH addresses require the redeemScript to extract pubkey hash")
	default:
		return result, fmt.Errorf("unsupported address type")
	}
}

// DetectAddressType determines the type of a Bitcoin address
func DetectAddressType(address string) AddressType {
	addr, err := btcutil.DecodeAddress(address, &chaincfg.MainNetParams)
	if err != nil {
		return AddressTypeUnknown
	}

	switch addr.(type) {
	case *btcutil.AddressPubKeyHash:
		return AddressTypeP2PKH
	case *btcutil.AddressWitnessPubKeyHash:
		return AddressTypeP2WPKH
	case *btcutil.AddressScriptHash:
		return AddressTypeP2SH
	case *btcutil.AddressTaproot:
		return AddressTypeP2TR
	case *btcutil.AddressWitnessScriptHash:
		return AddressTypeP2WSH
	default:
		return AddressTypeUnknown
	}
}

// TaprootAddressToXOnlyPubKey extracts the 32-byte x-only public key from a Taproot address
// Taproot addresses (bc1p...) directly encode the x-only public key
func TaprootAddressToXOnlyPubKey(address string) ([32]byte, error) {
	var result [32]byte

	addr, err := btcutil.DecodeAddress(address, &chaincfg.MainNetParams)
	if err != nil {
		return result, fmt.Errorf("invalid Bitcoin address: %w", err)
	}

	taprootAddr, ok := addr.(*btcutil.AddressTaproot)
	if !ok {
		return result, fmt.Errorf("not a Taproot address (expected bc1p...)")
	}

	// Get the witness program (32-byte x-only pubkey)
	witnessProgram := taprootAddr.WitnessProgram()
	if len(witnessProgram) != 32 {
		return result, fmt.Errorf("invalid Taproot witness program length: %d", len(witnessProgram))
	}

	copy(result[:], witnessProgram)
	return result, nil
}

// XOnlyPubKeyToTaprootAddress converts a 32-byte x-only public key to a Taproot address
func XOnlyPubKeyToTaprootAddress(xOnlyPubKey [32]byte) (string, error) {
	addr, err := btcutil.NewAddressTaproot(xOnlyPubKey[:], &chaincfg.MainNetParams)
	if err != nil {
		return "", fmt.Errorf("failed to create Taproot address: %w", err)
	}
	return addr.EncodeAddress(), nil
}

// P2SHAddressToScriptHash extracts the 20-byte script hash from a P2SH address
func P2SHAddressToScriptHash(address string) ([20]byte, error) {
	var result [20]byte

	addr, err := btcutil.DecodeAddress(address, &chaincfg.MainNetParams)
	if err != nil {
		return result, fmt.Errorf("invalid Bitcoin address: %w", err)
	}

	p2shAddr, ok := addr.(*btcutil.AddressScriptHash)
	if !ok {
		return result, fmt.Errorf("not a P2SH address (expected 3...)")
	}

	copy(result[:], p2shAddr.Hash160()[:])
	return result, nil
}

// ComputeP2SHP2WPKHScriptHash computes the script hash for a P2SH-wrapped P2WPKH
// The redeem script is: OP_0 <20-byte-pubkey-hash>
// Returns Hash160(0x0014 || pubkeyHash160)
func ComputeP2SHP2WPKHScriptHash(pubkeyHash160 [20]byte) [20]byte {
	// Build the witness program: OP_0 (0x00) + PUSH20 (0x14) + pubkeyHash160
	redeemScript := make([]byte, 22)
	redeemScript[0] = 0x00 // OP_0
	redeemScript[1] = 0x14 // Push 20 bytes
	copy(redeemScript[2:], pubkeyHash160[:])

	// Compute Hash160 of the redeem script
	return Hash160(redeemScript)
}

// Hash160 computes RIPEMD160(SHA256(data))
func Hash160(data []byte) [20]byte {
	var result [20]byte
	copy(result[:], btcutil.Hash160(data))
	return result
}

// VerifyP2SHP2WPKH verifies that a P2SH address wraps a specific public key's P2WPKH
func VerifyP2SHP2WPKH(p2shAddress string, pubkeyHash160 [20]byte) error {
	// Get the script hash from the P2SH address
	scriptHash, err := P2SHAddressToScriptHash(p2shAddress)
	if err != nil {
		return err
	}

	// Compute expected script hash
	expectedScriptHash := ComputeP2SHP2WPKHScriptHash(pubkeyHash160)

	// Compare
	if scriptHash != expectedScriptHash {
		return fmt.Errorf("P2SH address does not wrap the expected P2WPKH")
	}

	return nil
}

// PublicKeyToTaprootAddress computes the Taproot address from a public key.
// Per BIP-341, even for key-path-only spending (no script tree), the output key
// must be tweaked: Q = P + int(hashTapTweak(bytes(P)))G
// This ensures the address commits to an unspendable script path.
func PublicKeyToTaprootAddress(pubKey *btcec.PublicKey) (string, [32]byte, error) {
	var xOnly [32]byte

	// Apply BIP-341 taproot tweak for key-path only (no script tree)
	// This computes: output_key = internal_key + H(internal_key)*G
	outputKey := txscript.ComputeTaprootKeyNoScript(pubKey)

	// Get x-only output key (32 bytes)
	serialized := outputKey.SerializeCompressed()
	copy(xOnly[:], serialized[1:33])

	// Create Taproot address from the tweaked output key
	addr, err := btcutil.NewAddressTaproot(xOnly[:], &chaincfg.MainNetParams)
	if err != nil {
		return "", xOnly, fmt.Errorf("failed to create Taproot address: %w", err)
	}

	return addr.EncodeAddress(), xOnly, nil
}

// LiftXToPoint lifts an x-only public key to a full point (with even Y)
// This is used in BIP-340 Schnorr signature verification
func LiftXToPoint(xOnlyPubKey [32]byte) (*btcec.PublicKey, error) {
	// Prepend 0x02 for compressed pubkey with even Y
	compressed := make([]byte, 33)
	compressed[0] = 0x02
	copy(compressed[1:], xOnlyPubKey[:])

	pubKey, err := btcec.ParsePubKey(compressed)
	if err != nil {
		return nil, fmt.Errorf("invalid x-only public key: %w", err)
	}

	return pubKey, nil
}

// P2WSHAddressToWitnessProgram extracts the 32-byte witness program from a P2WSH address
// P2WSH addresses are bc1q... addresses with 62 characters (32-byte witness program)
func P2WSHAddressToWitnessProgram(address string) ([32]byte, error) {
	var result [32]byte

	addr, err := btcutil.DecodeAddress(address, &chaincfg.MainNetParams)
	if err != nil {
		return result, fmt.Errorf("invalid Bitcoin address: %w", err)
	}

	p2wshAddr, ok := addr.(*btcutil.AddressWitnessScriptHash)
	if !ok {
		return result, fmt.Errorf("not a P2WSH address")
	}

	// Get the witness program (32-byte SHA256 of witness script)
	witnessProgram := p2wshAddr.WitnessProgram()
	if len(witnessProgram) != 32 {
		return result, fmt.Errorf("invalid P2WSH witness program length: %d", len(witnessProgram))
	}

	copy(result[:], witnessProgram)
	return result, nil
}

// ComputeP2WSHSingleKeyWitnessProgram computes the witness program for a single-key P2WSH
// The witness script is: OP_PUSHBYTES_33 <compressed_pubkey> OP_CHECKSIG
// Returns SHA256(0x21 || compressed_pubkey || 0xAC)
func ComputeP2WSHSingleKeyWitnessProgram(compressedPubKey [33]byte) [32]byte {
	// Build the witness script: 0x21 || pubkey || 0xAC
	witnessScript := make([]byte, 35)
	witnessScript[0] = 0x21 // OP_PUSHBYTES_33
	copy(witnessScript[1:34], compressedPubKey[:])
	witnessScript[34] = 0xAC // OP_CHECKSIG

	// Return SHA256 of the witness script
	return sha256Sum(witnessScript)
}

// sha256Sum computes SHA256 hash
func sha256Sum(data []byte) [32]byte {
	return sha256.Sum256(data)
}

// WitnessProgramToP2WSHAddress converts a 32-byte witness program to a P2WSH address
func WitnessProgramToP2WSHAddress(witnessProgram [32]byte) (string, error) {
	addr, err := btcutil.NewAddressWitnessScriptHash(witnessProgram[:], &chaincfg.MainNetParams)
	if err != nil {
		return "", fmt.Errorf("failed to create P2WSH address: %w", err)
	}
	return addr.EncodeAddress(), nil
}

// IsP2WSHAddress returns true if the address is a P2WSH address
func IsP2WSHAddress(address string) bool {
	return DetectAddressType(address) == AddressTypeP2WSH
}
