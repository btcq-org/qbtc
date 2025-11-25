// Package main provides a CLI tool for generating ZK proofs
// to claim airdrops on the qbtc chain.
package main

import (
	"bufio"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/btcq-org/qbtc/x/qbtc/zk"
	"github.com/spf13/cobra"
	"golang.org/x/term"
)

func main() {
	rootCmd := &cobra.Command{
		Use:   "zkprover",
		Short: "ZK Proof Generator for qbtc airdrop claims",
		Long: `zkprover is a CLI tool for generating zero-knowledge proofs
that prove ownership of a Bitcoin address without revealing the private key.
These proofs can be used to claim airdrops on the qbtc chain.`,
	}

	rootCmd.AddCommand(
		setupCmd(),
		proveCmd(),
		addressCmd(),
		entropyCmd(),
	)

	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

// setupCmd creates the trusted setup command
func setupCmd() *cobra.Command {
	var outputDir string

	cmd := &cobra.Command{
		Use:   "setup",
		Short: "Generate the trusted setup (proving and verifying keys)",
		Long: `Generate the trusted setup for the ZK circuit.
This creates the proving key (for generating proofs) and verifying key (for verification).
The verifying key should be embedded in the chain for on-chain verification.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Println("Generating trusted setup...")
			fmt.Println("This may take a few minutes...")

			// Run the setup
			setup, err := zk.Setup()
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

			// Also save verifying key as hex for embedding
			vkHexPath := filepath.Join(outputDir, "verifying.key.hex")
			if err := os.WriteFile(vkHexPath, []byte(hex.EncodeToString(vkBytes)), 0644); err != nil {
				return fmt.Errorf("failed to write verifying key hex: %w", err)
			}
			fmt.Printf("Verifying key (hex) saved to: %s\n", vkHexPath)

			fmt.Println("\nSetup complete!")
			fmt.Println("Use the proving.key and circuit.cs files to generate proofs.")
			fmt.Println("Embed the verifying.key in the chain for on-chain verification.")

			return nil
		},
	}

	cmd.Flags().StringVarP(&outputDir, "output", "o", "./zk-setup", "Output directory for keys")

	return cmd
}

// proveCmd creates the prove command
func proveCmd() *cobra.Command {
	var (
		privateKeyHex   string
		privateKeyWIF   string
		btcqAddress     string
		setupDir        string
		outputFile      string
		useStdin        bool
	)

	cmd := &cobra.Command{
		Use:   "prove",
		Short: "Generate a ZK proof for an airdrop claim",
		Long: `Generate a zero-knowledge proof that proves ownership of a Bitcoin address.
The proof can be submitted to the qbtc chain to claim an airdrop.

You can provide your Bitcoin private key in hex format or WIF format.
The proof will be bound to your qbtc address to prevent replay attacks.

SECURITY: For better security, use --stdin to enter your private key interactively.
This prevents the key from appearing in shell history or process listings.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			// Parse the private key
			var privateKey *big.Int
			var err error

			if useStdin {
				// Read private key securely from stdin
				privateKey, err = readPrivateKeySecurely()
				if err != nil {
					return fmt.Errorf("failed to read private key: %w", err)
				}
			} else if privateKeyHex != "" {
				fmt.Fprintln(os.Stderr, "WARNING: Passing private key via command line is insecure.")
				fmt.Fprintln(os.Stderr, "         Consider using --stdin for better security.")
				privateKey, err = zk.PrivateKeyFromHex(privateKeyHex)
				if err != nil {
					return fmt.Errorf("invalid private key hex: %w", err)
				}
			} else if privateKeyWIF != "" {
				fmt.Fprintln(os.Stderr, "WARNING: Passing private key via command line is insecure.")
				fmt.Fprintln(os.Stderr, "         Consider using --stdin for better security.")
				privateKey, err = zk.PrivateKeyFromWIF(privateKeyWIF)
				if err != nil {
					return fmt.Errorf("invalid WIF: %w", err)
				}
			} else {
				return fmt.Errorf("must provide either --stdin, --private-key, or --wif")
			}

			// Clear private key from memory when done
			defer func() {
				if privateKey != nil {
					privateKey.SetInt64(0)
				}
			}()

			if btcqAddress == "" {
				return fmt.Errorf("--btcq-address is required")
			}

			// Compute the Bitcoin address hash
			addressHash, err := zk.PrivateKeyToAddressHash(privateKey)
			if err != nil {
				return fmt.Errorf("failed to compute address hash: %w", err)
			}
			fmt.Printf("Bitcoin address hash (Hash160): %s\n", hex.EncodeToString(addressHash[:]))

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

			// Compute btcq address hash for binding
			btcqAddressHash := zk.HashBTCQAddress(btcqAddress)

			// Generate the proof
			fmt.Println("Generating proof...")
			proof, err := prover.GenerateProof(privateKey, addressHash, btcqAddressHash)
			if err != nil {
				return fmt.Errorf("failed to generate proof: %w", err)
			}

			// Create the output
			output := ProofOutput{
				BTCAddressHash:  hex.EncodeToString(addressHash[:]),
				BTCQAddress:     btcqAddress,
				ProofData:       hex.EncodeToString(proof.ToProtoZKProof()),
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

	cmd.Flags().StringVar(&privateKeyHex, "private-key", "", "Bitcoin private key in hex format (INSECURE - use --stdin instead)")
	cmd.Flags().StringVar(&privateKeyWIF, "wif", "", "Bitcoin private key in WIF format (INSECURE - use --stdin instead)")
	cmd.Flags().BoolVar(&useStdin, "stdin", false, "Read private key securely from stdin (recommended)")
	cmd.Flags().StringVar(&btcqAddress, "btcq-address", "", "Your qbtc chain address (required)")
	cmd.Flags().StringVar(&setupDir, "setup-dir", "./zk-setup", "Directory containing setup files")
	cmd.Flags().StringVarP(&outputFile, "output", "o", "", "Output file for the proof (defaults to stdout)")

	return cmd
}

// readPrivateKeySecurely reads a private key from stdin without echoing
func readPrivateKeySecurely() (*big.Int, error) {
	fmt.Print("Enter private key format (hex/wif): ")
	reader := bufio.NewReader(os.Stdin)
	format, err := reader.ReadString('\n')
	if err != nil {
		return nil, err
	}
	format = strings.TrimSpace(strings.ToLower(format))

	fmt.Print("Enter private key: ")
	// Read password without echoing (if terminal)
	var keyBytes []byte
	if term.IsTerminal(int(syscall.Stdin)) {
		keyBytes, err = term.ReadPassword(int(syscall.Stdin))
		fmt.Println() // Print newline after password input
	} else {
		// Non-interactive mode, read from pipe
		keyInput, err := reader.ReadString('\n')
		if err != nil {
			return nil, err
		}
		keyBytes = []byte(strings.TrimSpace(keyInput))
	}
	if err != nil {
		return nil, err
	}

	keyStr := strings.TrimSpace(string(keyBytes))
	// Clear the key bytes from memory
	for i := range keyBytes {
		keyBytes[i] = 0
	}

	switch format {
	case "hex":
		return zk.PrivateKeyFromHex(keyStr)
	case "wif":
		return zk.PrivateKeyFromWIF(keyStr)
	default:
		return nil, fmt.Errorf("unknown format: %s (use 'hex' or 'wif')", format)
	}
}

// addressCmd creates the address utility command
func addressCmd() *cobra.Command {
	var (
		privateKeyHex string
		privateKeyWIF string
		btcAddress    string
	)

	cmd := &cobra.Command{
		Use:   "address",
		Short: "Utility commands for Bitcoin address operations",
		Long:  "Compute Bitcoin address hash from private key or extract from address",
	}

	// Sub-command to get address hash from private key
	fromKeyCmd := &cobra.Command{
		Use:   "from-key",
		Short: "Compute address hash from private key",
		RunE: func(cmd *cobra.Command, args []string) error {
			var privateKey *big.Int
			var err error

			if privateKeyHex != "" {
				privateKey, err = zk.PrivateKeyFromHex(privateKeyHex)
				if err != nil {
					return fmt.Errorf("invalid private key hex: %w", err)
				}
			} else if privateKeyWIF != "" {
				privateKey, err = zk.PrivateKeyFromWIF(privateKeyWIF)
				if err != nil {
					return fmt.Errorf("invalid WIF: %w", err)
				}
			} else {
				return fmt.Errorf("must provide either --private-key or --wif")
			}

			addressHash, err := zk.PrivateKeyToAddressHash(privateKey)
			if err != nil {
				return fmt.Errorf("failed to compute address hash: %w", err)
			}

			fmt.Printf("Address Hash (Hash160): %s\n", hex.EncodeToString(addressHash[:]))
			return nil
		},
	}
	fromKeyCmd.Flags().StringVar(&privateKeyHex, "private-key", "", "Bitcoin private key in hex format")
	fromKeyCmd.Flags().StringVar(&privateKeyWIF, "wif", "", "Bitcoin private key in WIF format")

	// Sub-command to extract address hash from Bitcoin address
	fromAddressCmd := &cobra.Command{
		Use:   "from-address",
		Short: "Extract address hash from Bitcoin address (P2PKH/P2WPKH only)",
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
	fromAddressCmd.Flags().StringVar(&btcAddress, "address", "", "Bitcoin address")

	cmd.AddCommand(fromKeyCmd, fromAddressCmd)

	return cmd
}

// ProofOutput is the JSON output structure for a generated proof
type ProofOutput struct {
	BTCAddressHash string `json:"btc_address_hash"`
	BTCQAddress    string `json:"btcq_address"`
	ProofData      string `json:"proof_data"`
}

// entropyCmd creates the entropy submission command for validators
func entropyCmd() *cobra.Command {
	var (
		validatorAddr string
		outputFile    string
	)

	cmd := &cobra.Command{
		Use:   "entropy",
		Short: "Generate entropy for the distributed ZK trusted setup",
		Long: `Generate cryptographically secure random entropy for the distributed
ZK trusted setup ceremony. This command is for validators participating
in the setup.

The generated entropy and commitment should be submitted to the chain
using the SubmitZKEntropy transaction.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if validatorAddr == "" {
				return fmt.Errorf("--validator is required")
			}

			// Generate 32 bytes of cryptographically secure random entropy
			entropy := make([]byte, 32)
			if _, err := rand.Read(entropy); err != nil {
				return fmt.Errorf("failed to generate entropy: %w", err)
			}

			// Compute commitment: SHA256(entropy || validator_address)
			hasher := sha256.New()
			hasher.Write(entropy)
			hasher.Write([]byte(validatorAddr))
			commitment := hasher.Sum(nil)

			// Create output
			output := EntropyOutput{
				Validator:  validatorAddr,
				Entropy:    hex.EncodeToString(entropy),
				Commitment: hex.EncodeToString(commitment),
			}

			// Serialize to JSON
			outputBytes, err := json.MarshalIndent(output, "", "  ")
			if err != nil {
				return fmt.Errorf("failed to serialize output: %w", err)
			}

			// Write to file or stdout
			if outputFile != "" {
				// Use restrictive permissions for the entropy file
				if err := os.WriteFile(outputFile, outputBytes, 0600); err != nil {
					return fmt.Errorf("failed to write output: %w", err)
				}
				fmt.Printf("Entropy saved to: %s\n", outputFile)
				fmt.Println("\nIMPORTANT: Keep this file secure! The entropy value should")
				fmt.Println("be kept secret until you submit it to the chain.")
			} else {
				fmt.Println(string(outputBytes))
			}

			fmt.Println("\nEntropy generation complete!")
			fmt.Println("Submit this to the chain using: qbtcd tx qbtc submit-zk-entropy ...")

			return nil
		},
	}

	cmd.Flags().StringVar(&validatorAddr, "validator", "", "Your validator address (required)")
	cmd.Flags().StringVarP(&outputFile, "output", "o", "", "Output file for the entropy (defaults to stdout)")

	return cmd
}

// EntropyOutput is the JSON output structure for generated entropy
type EntropyOutput struct {
	Validator  string `json:"validator"`
	Entropy    string `json:"entropy"`
	Commitment string `json:"commitment"`
}
