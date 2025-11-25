// Package main provides a TSS (Threshold Signature Scheme) emulator HTTP service.
// This emulator simulates a TSS signer by exposing only a signing API while
// keeping the private key internal. It's used for testing and development
// of the signature-based ZK proof system.
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/btcsuite/btcd/btcec/v2"
	btcecdsa "github.com/btcsuite/btcd/btcec/v2/ecdsa"
	"github.com/spf13/cobra"
	"golang.org/x/crypto/ripemd160"
)

// SignRequest is the JSON request body for the /sign endpoint
type SignRequest struct {
	MessageHash string `json:"message_hash"` // 32-byte message hash in hex (64 chars)
}

// SignatureData contains the ECDSA signature components
type SignatureData struct {
	R string `json:"r"` // R component in hex
	S string `json:"s"` // S component in hex
	V int    `json:"v"` // Recovery ID (0 or 1)
}

// SignResponse is the JSON response from the /sign endpoint
type SignResponse struct {
	Signature SignatureData `json:"signature"`
	PublicKey string        `json:"public_key"` // Compressed public key in hex (33 bytes)
}

// ErrorResponse is returned on errors
type ErrorResponse struct {
	Error string `json:"error"`
}

// TSSEmulator holds the internal state of the emulator
type TSSEmulator struct {
	privateKey *btcec.PrivateKey
	publicKey  *btcec.PublicKey
}

// NewTSSEmulator creates a new TSS emulator with the given private key
func NewTSSEmulator(privateKeyHex string) (*TSSEmulator, error) {
	// Decode the private key
	pkBytes, err := hex.DecodeString(privateKeyHex)
	if err != nil {
		return nil, fmt.Errorf("invalid private key hex: %w", err)
	}

	if len(pkBytes) != 32 {
		return nil, fmt.Errorf("private key must be 32 bytes, got %d", len(pkBytes))
	}

	// Create the private key
	privKey, pubKey := btcec.PrivKeyFromBytes(pkBytes)

	return &TSSEmulator{
		privateKey: privKey,
		publicKey:  pubKey,
	}, nil
}

// Sign signs a message hash and returns the signature components
func (t *TSSEmulator) Sign(messageHash []byte) (*SignResponse, error) {
	if len(messageHash) != 32 {
		return nil, fmt.Errorf("message hash must be 32 bytes, got %d", len(messageHash))
	}

	// Sign the message using ECDSA
	sig := btcecdsa.Sign(t.privateKey, messageHash)

	// Serialize the signature to get R and S bytes
	// DER format, but we can also use the compact format
	sigBytes := sig.Serialize()

	// Parse R and S from the DER signature
	// DER: 0x30 [total-len] 0x02 [r-len] [r] 0x02 [s-len] [s]
	rLen := int(sigBytes[3])
	rBytes := sigBytes[4 : 4+rLen]
	sLen := int(sigBytes[4+rLen+1])
	sBytes := sigBytes[4+rLen+2 : 4+rLen+2+sLen]

	// Remove leading zero bytes (DER uses signed integers)
	if len(rBytes) > 0 && rBytes[0] == 0 {
		rBytes = rBytes[1:]
	}
	if len(sBytes) > 0 && sBytes[0] == 0 {
		sBytes = sBytes[1:]
	}

	// Compute recovery ID (v)
	v := t.computeRecoveryID(messageHash, rBytes, sBytes)

	// Get compressed public key
	compressedPubKey := t.publicKey.SerializeCompressed()

	return &SignResponse{
		Signature: SignatureData{
			R: hex.EncodeToString(rBytes),
			S: hex.EncodeToString(sBytes),
			V: v,
		},
		PublicKey: hex.EncodeToString(compressedPubKey),
	}, nil
}

// computeRecoveryID determines the recovery ID for the signature
func (t *TSSEmulator) computeRecoveryID(messageHash []byte, rBytes, sBytes []byte) int {
	// Pad to 32 bytes for compact signature format
	rPadded := make([]byte, 32)
	sPadded := make([]byte, 32)
	copy(rPadded[32-len(rBytes):], rBytes)
	copy(sPadded[32-len(sBytes):], sBytes)

	// Create signature bytes for recovery (compact format)
	sigBytes := make([]byte, 65)
	sigBytes[0] = 27 // Recovery flag for v=0
	copy(sigBytes[1:33], rPadded)
	copy(sigBytes[33:65], sPadded)

	recoveredPub, _, err := btcecdsa.RecoverCompact(sigBytes, messageHash)
	if err == nil && recoveredPub.IsEqual(t.publicKey) {
		return 0
	}

	// Try with v=1
	sigBytes[0] = 28
	recoveredPub, _, err = btcecdsa.RecoverCompact(sigBytes, messageHash)
	if err == nil && recoveredPub.IsEqual(t.publicKey) {
		return 1
	}

	// Default to 0 if we can't determine (shouldn't happen)
	return 0
}

// GetPublicKeyHash returns the Hash160 of the public key (for display purposes)
func (t *TSSEmulator) GetPublicKeyHash() []byte {
	compressedPubKey := t.publicKey.SerializeCompressed()
	return hash160(compressedPubKey)
}

// hash160 computes RIPEMD160(SHA256(data))
func hash160(data []byte) []byte {
	sha := sha256.Sum256(data)
	ripemd := ripemd160.New()
	ripemd.Write(sha[:])
	return ripemd.Sum(nil)
}

func main() {
	var (
		port          string
		privateKeyHex string
	)

	rootCmd := &cobra.Command{
		Use:   "tss-emulator",
		Short: "TSS Emulator - A threshold signature scheme emulator for testing",
		Long: `TSS Emulator is an HTTP service that emulates a Threshold Signature Scheme (TSS) signer.
It exposes only a signing API endpoint while keeping the private key internal.
This is used for testing and development of the signature-based ZK proof system.

The emulator accepts a private key via flag or environment variable (TSS_PRIVATE_KEY)
and provides a /sign endpoint that returns ECDSA signatures.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			// Get private key from flag or environment
			if privateKeyHex == "" {
				privateKeyHex = os.Getenv("TSS_PRIVATE_KEY")
			}
			if privateKeyHex == "" {
				return fmt.Errorf("private key required: use --private-key flag or TSS_PRIVATE_KEY env var")
			}

			// Create the emulator
			emulator, err := NewTSSEmulator(privateKeyHex)
			if err != nil {
				return fmt.Errorf("failed to create emulator: %w", err)
			}

			// Log startup info (public key only, never the private key)
			pubKeyHex := hex.EncodeToString(emulator.publicKey.SerializeCompressed())
			addrHash := hex.EncodeToString(emulator.GetPublicKeyHash())
			log.Printf("TSS Emulator starting...")
			log.Printf("Public Key: %s", pubKeyHex)
			log.Printf("Address Hash (Hash160): %s", addrHash)
			log.Printf("Listening on %s", port)

			// Set up HTTP handlers
			http.HandleFunc("/sign", func(w http.ResponseWriter, r *http.Request) {
				handleSign(w, r, emulator)
			})

			http.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
			})

			http.HandleFunc("/info", func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(map[string]string{
					"public_key":   pubKeyHex,
					"address_hash": addrHash,
				})
			})

			// Start the server
			return http.ListenAndServe(port, nil)
		},
	}

	rootCmd.Flags().StringVarP(&port, "port", "p", ":8080", "Port to listen on")
	rootCmd.Flags().StringVar(&privateKeyHex, "private-key", "", "Private key in hex format (or use TSS_PRIVATE_KEY env var)")

	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

// handleSign handles the POST /sign endpoint
func handleSign(w http.ResponseWriter, r *http.Request, emulator *TSSEmulator) {
	w.Header().Set("Content-Type", "application/json")

	// Only accept POST
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		_ = json.NewEncoder(w).Encode(ErrorResponse{Error: "method not allowed, use POST"})
		return
	}

	// Parse request body
	var req SignRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(ErrorResponse{Error: fmt.Sprintf("invalid JSON: %v", err)})
		return
	}

	// Validate message hash
	messageHash, err := hex.DecodeString(req.MessageHash)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(ErrorResponse{Error: fmt.Sprintf("invalid message_hash hex: %v", err)})
		return
	}

	if len(messageHash) != 32 {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(ErrorResponse{Error: fmt.Sprintf("message_hash must be 32 bytes (64 hex chars), got %d bytes", len(messageHash))})
		return
	}

	// Sign the message
	response, err := emulator.Sign(messageHash)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		_ = json.NewEncoder(w).Encode(ErrorResponse{Error: fmt.Sprintf("signing failed: %v", err)})
		return
	}

	log.Printf("Signed message: %s", req.MessageHash)

	// Return the signature
	_ = json.NewEncoder(w).Encode(response)
}
