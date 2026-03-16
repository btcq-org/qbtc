// Quick tool to verify an MLDSA signature against a SignDoc.
// Usage: go run ./cmd/verify-sig <signDocHex> <signatureHex> <pubKeyHex> [sha256HashHex]
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"

	"github.com/cloudflare/circl/sign/mldsa/mldsa44"
)

func main() {
	if len(os.Args) < 4 {
		fmt.Fprintf(os.Stderr, "Usage: %s <signDocHex> <signatureHex> <pubKeyHex> [sha256HashHex]\n", os.Args[0])
		os.Exit(1)
	}

	signDocBytes, err := hex.DecodeString(os.Args[1])
	if err != nil {
		fmt.Fprintf(os.Stderr, "invalid signDoc hex: %v\n", err)
		os.Exit(1)
	}
	sigBytes, err := hex.DecodeString(os.Args[2])
	if err != nil {
		fmt.Fprintf(os.Stderr, "invalid signature hex: %v\n", err)
		os.Exit(1)
	}
	pubKeyBytes, err := hex.DecodeString(os.Args[3])
	if err != nil {
		fmt.Fprintf(os.Stderr, "invalid pubKey hex: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("SignDoc:    %d bytes\n", len(signDocBytes))
	fmt.Printf("Signature: %d bytes (expected %d)\n", len(sigBytes), mldsa44.SignatureSize)
	fmt.Printf("PubKey:    %d bytes (expected %d)\n", len(pubKeyBytes), mldsa44.PublicKeySize)

	if len(sigBytes) != mldsa44.SignatureSize {
		fmt.Printf("FAIL: signature size mismatch\n")
		os.Exit(1)
	}
	if len(pubKeyBytes) != mldsa44.PublicKeySize {
		fmt.Printf("FAIL: pubkey size mismatch\n")
		os.Exit(1)
	}

	scheme := mldsa44.Scheme()
	publicKey, err := scheme.UnmarshalBinaryPublicKey(pubKeyBytes)
	if err != nil {
		fmt.Printf("FAIL: cannot unmarshal pubkey: %v\n", err)
		os.Exit(1)
	}

	// Compute SHA256 of signDoc (what cosmos-sdk does)
	shaMsg := sha256.Sum256(signDocBytes)
	fmt.Printf("\nGo SHA256(signDoc): %x\n", shaMsg)

	// If iOS SHA256 hash was provided, compare
	if len(os.Args) >= 5 {
		iosHashBytes, err := hex.DecodeString(os.Args[4])
		if err == nil {
			fmt.Printf("iOS SHA256 hash:    %x\n", iosHashBytes)
			if hex.EncodeToString(shaMsg[:]) == hex.EncodeToString(iosHashBytes) {
				fmt.Println("SHA256 hashes MATCH between Go and iOS ✓")
			} else {
				fmt.Println("SHA256 hashes DIFFER! SignDoc encoding mismatch between iOS and Go!")
			}

			// Try verifying against the iOS hash directly
			resultIOS := scheme.Verify(publicKey, iosHashBytes, sigBytes, nil)
			fmt.Printf("Verify(iosHash, sig)         = %v\n", resultIOS)
			if resultIOS {
				fmt.Println("\nThe TSS signed the iOS SHA256 hash. Issue is signDoc encoding difference.")
			}
		}
	}

	fmt.Println()

	// Test 1: Verify with SHA256 (what the cosmos-sdk MLDSA does)
	result1 := scheme.Verify(publicKey, shaMsg[:], sigBytes, nil)
	fmt.Printf("Verify(SHA256(signDoc), sig) = %v\n", result1)

	// Test 2: Verify with raw signDoc
	result2 := scheme.Verify(publicKey, signDocBytes, sigBytes, nil)
	fmt.Printf("Verify(signDoc, sig)         = %v\n", result2)

	// Test 3: Verify with SHA256(SHA256(signDoc))
	shaMsg2 := sha256.Sum256(shaMsg[:])
	result3 := scheme.Verify(publicKey, shaMsg2[:], sigBytes, nil)
	fmt.Printf("Verify(SHA256(SHA256), sig)   = %v\n", result3)

	// Test 5: What if the TSS signed the hex string instead of decoded bytes?
	hexStr := hex.EncodeToString(shaMsg[:])
	result5 := scheme.Verify(publicKey, []byte(hexStr), sigBytes, nil)
	fmt.Printf("Verify(hexString(SHA256), sig)= %v  (TSS signed hex string?)\n", result5)

	if result1 {
		fmt.Println("\nSUCCESS: cosmos-sdk verification works (SHA256 + MLDSA)")
	} else if result2 {
		fmt.Println("\nFIX: TSS signed raw signDoc. Remove SHA256 in getPreSignedImageHash.")
	} else if result3 {
		fmt.Println("\nFIX: Double SHA256. TSS hashes internally. Remove SHA256 in getPreSignedImageHash.")
	} else if result5 {
		fmt.Println("\nFIX: TSS signed the hex string, not the decoded bytes!")
		fmt.Println("     The hex-encoded hash string was passed as-is to the TSS instead of being decoded.")
	} else {
		fmt.Println("\nFAIL: No verification method works.")
		fmt.Println("Possible causes:")
		fmt.Println("  1. vscore MLDSA implementation not interoperable with cloudflare/circl")
		fmt.Println("  2. Key derivation: TSS used a derived key, pubkey is the master key")
		fmt.Println("  3. Signature was produced by a different signing session/message")
	}
}
