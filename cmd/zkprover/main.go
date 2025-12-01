// Package main provides a CLI tool for generating ZK proofs
// to claim airdrops on the qbtc chain using TSS-compatible signatures.
package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"os"
	"path/filepath"

	"github.com/btcq-org/qbtc/x/qbtc/zk"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/spf13/cobra"
)

func main() {
	rootCmd := &cobra.Command{
		Use:   "zkprover",
		Short: "ZK Proof Generator for qbtc airdrop claims (TSS compatible)",
		Long: `zkprover is a CLI tool for generating zero-knowledge proofs
that prove ownership of a Bitcoin address using ECDSA signatures.
These proofs can be used to claim airdrops on the qbtc chain.

This tool is TSS/MPC compatible - it only requires a signature, not
direct access to the private key. The proof hides both the signature
and public key from on-chain observers.

Uses PLONK proof system with Hermez Powers of Tau ceremony SRS.`,
	}

	rootCmd.AddCommand(
		setupCmd(),
		proveCmd(),
		addressCmd(),
	)

	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

// setupCmd creates the trusted setup command
func setupCmd() *cobra.Command {
	var (
		outputDir string
		testMode  bool
		cacheDir  string
	)

	cmd := &cobra.Command{
		Use:   "setup",
		Short: "Generate PLONK trusted setup (proving and verifying keys)",
		Long: `Generate the trusted setup for the ZK circuit using PLONK.
This creates the proving key (for generating proofs) and verifying key (for verification).
The verifying key should be embedded in the chain's genesis for on-chain verification.

By default, this command downloads and uses the Hermez/Polygon Powers of Tau
ceremony SRS, which is a production-ready trusted setup. The SRS is cached
locally for future use.

Use --test flag only for development/testing with an unsafe test SRS.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Println("Generating PLONK trusted setup...")
			fmt.Println("This may take a few minutes...")

			var opts zk.SetupOptions
			if testMode {
				fmt.Println("")
				fmt.Println("⚠️  WARNING: Using UNSAFE test SRS!")
				fmt.Println("⚠️  DO NOT use these keys in production!")
				fmt.Println("⚠️  Anyone can forge proofs with test SRS keys.")
				fmt.Println("")
				opts = zk.TestSetupOptions()
			} else {
				fmt.Println("")
				fmt.Println("✓ Using Hermez/Polygon Powers of Tau ceremony SRS")
				fmt.Println("✓ This is a production-ready trusted setup")
				fmt.Println("")
				opts = zk.DefaultSetupOptions()
				if cacheDir != "" {
					opts.CacheDir = cacheDir
				}
			}

			// Run the setup
			setup, err := zk.SetupWithOptions(opts)
			if err != nil {
				return fmt.Errorf("setup failed: %w", err)
			}

			// Create output directory
			if err := os.MkdirAll(outputDir, 0755); err != nil {
				return fmt.Errorf("failed to create output directory: %w", err)
			}

			// Save constraint system
			csPath := filepath.Join(outputDir, "circuit.cs")
			csBytes, err := zk.SerializeConstraintSystem(setup.ConstraintSystem)
			if err != nil {
				return fmt.Errorf("failed to serialize constraint system: %w", err)
			}
			if err := os.WriteFile(csPath, csBytes, 0644); err != nil {
				return fmt.Errorf("failed to write constraint system: %w", err)
			}
			fmt.Printf("Constraint system saved to: %s\n", csPath)

			// Save proving key
			pkPath := filepath.Join(outputDir, "proving.key")
			pkBytes, err := zk.SerializeProvingKey(setup.ProvingKey)
			if err != nil {
				return fmt.Errorf("failed to serialize proving key: %w", err)
			}
			if err := os.WriteFile(pkPath, pkBytes, 0644); err != nil {
				return fmt.Errorf("failed to write proving key: %w", err)
			}
			fmt.Printf("Proving key saved to: %s\n", pkPath)

			// Save verifying key
			vkPath := filepath.Join(outputDir, "verifying.key")
			vkBytes, err := zk.SerializeVerifyingKey(setup.VerifyingKey)
			if err != nil {
				return fmt.Errorf("failed to serialize verifying key: %w", err)
			}
			if err := os.WriteFile(vkPath, vkBytes, 0644); err != nil {
				return fmt.Errorf("failed to write verifying key: %w", err)
			}
			fmt.Printf("Verifying key saved to: %s\n", vkPath)

			// Also save verifying key as hex for embedding in genesis
			vkHexPath := filepath.Join(outputDir, "verifying.key.hex")
			if err := os.WriteFile(vkHexPath, []byte(hex.EncodeToString(vkBytes)), 0644); err != nil {
				return fmt.Errorf("failed to write verifying key hex: %w", err)
			}
			fmt.Printf("Verifying key (hex) saved to: %s\n", vkHexPath)

			fmt.Println("\nSetup complete!")
			fmt.Println("Use the proving.key and circuit.cs files to generate proofs.")
			fmt.Println("Add the verifying.key.hex content to genesis.json as zk_verifying_key.")

			if testMode {
				fmt.Println("")
				fmt.Println("⚠️  REMINDER: These are TEST keys - do not use in production!")
			}

			return nil
		},
	}

	cmd.Flags().StringVarP(&outputDir, "output", "o", "./zk-setup", "Output directory for keys")
	cmd.Flags().BoolVar(&testMode, "test", false, "Use unsafe test SRS (development only, DO NOT use in production)")
	cmd.Flags().StringVar(&cacheDir, "cache-dir", "", "Directory to cache downloaded SRS files (default: ~/.qbtc/zk-cache)")

	return cmd
}

// proveCmd creates the prove command for TSS-compatible proof generation
func proveCmd() *cobra.Command {
	var (
		tssURL         string
		btcqAddress    string
		chainID        string
		addressHashHex string
		setupDir       string
		outputFile     string
	)

	cmd := &cobra.Command{
		Use:   "prove",
		Short: "Generate a ZK proof using TSS signer (no private key required)",
		Long: `Generate a zero-knowledge proof using a TSS (Threshold Signature Scheme) signer.
This command is compatible with MPC/TSS systems that cannot reveal private keys.

The command will:
1. Compute the claim message hash
2. Request a signature from the TSS signer API
3. Generate a ZK proof that the signature is valid for the claimed address

The proof proves ownership without revealing the signature or public key.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if tssURL == "" {
				return fmt.Errorf("--tss-url is required")
			}
			if btcqAddress == "" {
				return fmt.Errorf("--btcq-address is required")
			}
			if chainID == "" {
				return fmt.Errorf("--chain-id is required")
			}
			if addressHashHex == "" {
				return fmt.Errorf("--address-hash is required (Hash160 of your Bitcoin address)")
			}

			// Parse address hash
			addressHash, err := zk.AddressHashFromHex(addressHashHex)
			if err != nil {
				return fmt.Errorf("invalid address hash: %w", err)
			}

			// Compute btcq address hash for binding
			btcqAddressHash := zk.HashBTCQAddress(btcqAddress)

			// Compute chain ID hash
			chainIDHash := zk.ComputeChainIDHash(chainID)

			// Compute the claim message that TSS needs to sign
			messageHash := zk.ComputeClaimMessage(addressHash, btcqAddressHash, chainIDHash)
			fmt.Printf("Message to sign: %s\n", hex.EncodeToString(messageHash[:]))

			// Request signature from TSS
			fmt.Printf("Requesting signature from TSS at %s...\n", tssURL)
			signResp, err := requestTSSSignature(tssURL, messageHash)
			if err != nil {
				return fmt.Errorf("failed to get TSS signature: %w", err)
			}
			fmt.Println("Received signature from TSS")

			// Parse the signature components
			rBytes, err := hex.DecodeString(signResp.Signature.R)
			if err != nil {
				return fmt.Errorf("invalid signature R: %w", err)
			}
			sBytes, err := hex.DecodeString(signResp.Signature.S)
			if err != nil {
				return fmt.Errorf("invalid signature S: %w", err)
			}
			pubKeyBytes, err := hex.DecodeString(signResp.PublicKey)
			if err != nil {
				return fmt.Errorf("invalid public key: %w", err)
			}

			// Parse public key to get X, Y coordinates
			pubKey, err := btcec.ParsePubKey(pubKeyBytes)
			if err != nil {
				return fmt.Errorf("failed to parse public key: %w", err)
			}

			// Verify the public key matches the claimed address hash
			computedHash, err := zk.PublicKeyToAddressHash(pubKey.SerializeCompressed())
			if err != nil {
				return fmt.Errorf("failed to compute address hash from public key: %w", err)
			}
			if !bytes.Equal(computedHash[:], addressHash[:]) {
				return fmt.Errorf("public key from TSS does not match claimed address hash")
			}
			fmt.Println("Public key verified against address hash")

			// Convert to big.Int for the prover
			sigR := new(big.Int).SetBytes(padTo32Bytes(rBytes))
			sigS := new(big.Int).SetBytes(padTo32Bytes(sBytes))
			pubKeyX := pubKey.X()
			pubKeyY := pubKey.Y()

			// Load the setup files
			csPath := filepath.Join(setupDir, "circuit.cs")
			csBytes, err := os.ReadFile(csPath)
			if err != nil {
				return fmt.Errorf("failed to read constraint system: %w", err)
			}
			cs, err := zk.DeserializeConstraintSystem(csBytes)
			if err != nil {
				return fmt.Errorf("failed to deserialize constraint system: %w", err)
			}

			pkPath := filepath.Join(setupDir, "proving.key")
			pkBytes, err := os.ReadFile(pkPath)
			if err != nil {
				return fmt.Errorf("failed to read proving key: %w", err)
			}
			pk, err := zk.DeserializeProvingKey(pkBytes)
			if err != nil {
				return fmt.Errorf("failed to deserialize proving key: %w", err)
			}

			// Create prover
			prover := zk.NewProver(cs, pk)

			// Generate the proof
			fmt.Println("Generating PLONK proof...")
			proof, err := prover.GenerateProof(zk.ProofParams{
				SignatureR:      sigR,
				SignatureS:      sigS,
				PublicKeyX:      pubKeyX,
				PublicKeyY:      pubKeyY,
				MessageHash:     messageHash,
				AddressHash:     addressHash,
				BTCQAddressHash: btcqAddressHash,
				ChainID:         chainIDHash,
			})
			if err != nil {
				return fmt.Errorf("failed to generate proof: %w", err)
			}

			// Create the output
			output := ProofOutput{
				BTCAddressHash: hex.EncodeToString(addressHash[:]),
				BTCQAddress:    btcqAddress,
				ChainID:        chainID,
				MessageHash:    hex.EncodeToString(messageHash[:]),
				ProofData:      hex.EncodeToString(proof),
			}

			// Serialize to JSON
			outputBytes, err := json.MarshalIndent(output, "", "  ")
			if err != nil {
				return fmt.Errorf("failed to serialize output: %w", err)
			}

			// Write to file or stdout
			if outputFile != "" {
				if err := os.WriteFile(outputFile, outputBytes, 0644); err != nil {
					return fmt.Errorf("failed to write output: %w", err)
				}
				fmt.Printf("Proof saved to: %s\n", outputFile)
			} else {
				fmt.Println(string(outputBytes))
			}

			fmt.Println("\nProof generation complete!")
			fmt.Println("Submit this proof to the qbtc chain to claim your airdrop.")

			return nil
		},
	}

	cmd.Flags().StringVar(&tssURL, "tss-url", "", "URL of the TSS signer API (required, e.g., http://localhost:8080)")
	cmd.Flags().StringVar(&btcqAddress, "btcq-address", "", "Your qbtc chain address (required)")
	cmd.Flags().StringVar(&chainID, "chain-id", "", "Chain ID for the proof (required, e.g., 'qbtc-1')")
	cmd.Flags().StringVar(&addressHashHex, "address-hash", "", "Hash160 of your Bitcoin address in hex (required)")
	cmd.Flags().StringVar(&setupDir, "setup-dir", "./zk-setup", "Directory containing setup files")
	cmd.Flags().StringVarP(&outputFile, "output", "o", "", "Output file for the proof (defaults to stdout)")

	return cmd
}

// addressCmd creates the address utility command
func addressCmd() *cobra.Command {
	var btcAddress string

	cmd := &cobra.Command{
		Use:   "address",
		Short: "Extract address hash from Bitcoin address (P2PKH/P2WPKH only)",
		Long:  "Extract the Hash160 address hash from a Bitcoin address for use with --address-hash",
		RunE: func(cmd *cobra.Command, args []string) error {
			if btcAddress == "" {
				return fmt.Errorf("--address is required")
			}

			addressHash, err := zk.BitcoinAddressToHash160(btcAddress)
			if err != nil {
				return fmt.Errorf("failed to extract address hash: %w", err)
			}

			fmt.Printf("Address Hash (Hash160): %s\n", hex.EncodeToString(addressHash[:]))
			return nil
		},
	}

	cmd.Flags().StringVar(&btcAddress, "address", "", "Bitcoin address (P2PKH or P2WPKH)")
	return cmd
}

// ProofOutput is the JSON output structure for a generated proof
type ProofOutput struct {
	BTCAddressHash string `json:"btc_address_hash"`
	BTCQAddress    string `json:"btcq_address"`
	ChainID        string `json:"chain_id"`
	MessageHash    string `json:"message_hash"`
	ProofData      string `json:"proof_data"`
}

// TSSSignRequest is the request body for the TSS /sign endpoint
type TSSSignRequest struct {
	MessageHash string `json:"message_hash"`
}

// TSSSignatureData contains the ECDSA signature components from TSS
type TSSSignatureData struct {
	R string `json:"r"`
	S string `json:"s"`
	V int    `json:"v"`
}

// TSSSignResponse is the response from the TSS /sign endpoint
type TSSSignResponse struct {
	Signature TSSSignatureData `json:"signature"`
	PublicKey string           `json:"public_key"`
}

// requestTSSSignature requests a signature from the TSS emulator
func requestTSSSignature(tssURL string, messageHash [32]byte) (*TSSSignResponse, error) {
	// Prepare request
	reqBody := TSSSignRequest{
		MessageHash: hex.EncodeToString(messageHash[:]),
	}
	reqBytes, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	// Make HTTP request
	resp, err := http.Post(tssURL+"/sign", "application/json", bytes.NewReader(reqBytes))
	if err != nil {
		return nil, fmt.Errorf("HTTP request failed: %w", err)
	}
	defer resp.Body.Close()

	// Read response
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("TSS returned error: %s", string(respBody))
	}

	// Parse response
	var signResp TSSSignResponse
	if err := json.Unmarshal(respBody, &signResp); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	return &signResp, nil
}

// padTo32Bytes pads a byte slice to 32 bytes (left-padded with zeros)
func padTo32Bytes(b []byte) []byte {
	if len(b) >= 32 {
		return b
	}
	padded := make([]byte, 32)
	copy(padded[32-len(b):], b)
	return padded
}
