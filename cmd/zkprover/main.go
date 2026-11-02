// Package main provides a CLI tool for generating ZK proofs to claim UTXOs on
// the qbtc chain from a Bitcoin wallet's signed message.
package main

import (
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"

	"github.com/btcq-org/qbtc/x/qbtc/zk"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/spf13/cobra"
)

func main() {
	rootCmd := &cobra.Command{
		Use:   "zkprover",
		Short: "ZK proof generator for qbtc claims",
		Long: `zkprover generates zero-knowledge proofs that prove ownership of a
Bitcoin address from a signed message, so the UTXOs of that address can be
claimed on the qbtc chain.

Flow:
  1. zkprover message ...      prints the text to sign
  2. sign that text in your Bitcoin wallet ("Sign message", BIP-137)
  3. zkprover prove --signature <base64> ...
  4. qbtcd tx qbtc claim-with-proof <output file> --from <key>

Any wallet that signs messages works (Electrum, Sparrow, Ledger, Trezor,
Bitcoin Core for legacy addresses). A TSS/MPC signer can be used instead
with --tss-url. The proof hides both the signature and the public key.

Uses PLONK proof system with Hermez Powers of Tau ceremony SRS.`,
	}

	rootCmd.AddCommand(
		setupCmd(),
		messageCmd(),
		proveCmd(),
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

// addTargetFlags adds the flags that identify what is being claimed.
func addTargetFlags(cmd *cobra.Command, t *claimTarget) {
	cmd.Flags().StringVar(&t.chainID, "chain-id", "", "Chain ID of the qbtc chain (required, e.g. 'qbtc-1')")
	cmd.Flags().StringVar(&t.bitcoinAddress, "bitcoin-address", "", "Bitcoin address being claimed, exactly as stored on the UTXO (required, P2PKH or P2WPKH)")
	cmd.Flags().StringVar(&t.claimer, "claimer", "", "qbtc address that claims the UTXOs (required)")
	cmd.Flags().StringVar(&t.receiver, "receiver", "", "qbtc address that receives the coins instead of the claimer (optional)")
}

func (c *claimTarget) validate() error {
	switch {
	case c.chainID == "":
		return fmt.Errorf("--chain-id is required")
	case c.bitcoinAddress == "":
		return fmt.Errorf("--bitcoin-address is required")
	case c.claimer == "":
		return fmt.Errorf("--claimer is required")
	}
	if _, err := zk.BitcoinAddressToHash160(c.bitcoinAddress); err != nil {
		return fmt.Errorf("--bitcoin-address: %w", err)
	}
	if err := zk.CheckBitcoinAddressCanonical(c.bitcoinAddress); err != nil {
		return fmt.Errorf("--bitcoin-address: %w", err)
	}
	return nil
}

// messageCmd prints the exact text the user must sign in their wallet.
func messageCmd() *cobra.Command {
	var target claimTarget

	cmd := &cobra.Command{
		Use:   "message",
		Short: "Print the claim message to sign in your Bitcoin wallet",
		Long: `Print the exact text to sign with your Bitcoin wallet's "Sign message"
feature (BIP-137). Sign it with the key of --bitcoin-address, then pass the
base64 signature to 'zkprover prove --signature'.

The text is printed on stdout; the BIP-137 digest a TSS signer would sign is
printed on stderr.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := target.validate(); err != nil {
				return err
			}
			digest := target.digest()
			fmt.Fprintf(os.Stderr, "Digest (for TSS signers): %s\n", hex.EncodeToString(digest[:]))
			fmt.Println(target.messageText())
			return nil
		},
	}
	addTargetFlags(cmd, &target)
	return cmd
}

// proveCmd generates the proof and writes a ready-to-submit MsgClaimWithProof.
func proveCmd() *cobra.Command {
	var (
		target     claimTarget
		utxoFlags  []string
		signature  string
		tssURL     string
		setupDir   string
		outputFile string
	)

	cmd := &cobra.Command{
		Use:   "prove",
		Short: "Generate a ZK proof from a signed claim message",
		Long: `Generate a zero-knowledge proof of Bitcoin address ownership from a signed
claim message, and write the MsgClaimWithProof JSON that
'qbtcd tx qbtc claim-with-proof' submits.

The signature comes from one of:
  --signature <base64>   a BIP-137 signature of 'zkprover message' output,
                         made by your Bitcoin wallet
  --tss-url <url>        a TSS/MPC signer exposing POST /sign; it signs the
                         32-byte BIP-137 digest of the claim message

The proof hides the signature and public key; only SHA256 of the compressed
public key is revealed, which the chain checks against the address.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := target.validate(); err != nil {
				return err
			}
			if len(utxoFlags) == 0 {
				return fmt.Errorf("at least one --utxo txid:vout is required")
			}
			for _, u := range utxoFlags {
				ref, err := parseUTXORef(u)
				if err != nil {
					return err
				}
				target.utxos = append(target.utxos, ref)
			}
			if (signature == "") == (tssURL == "") {
				return fmt.Errorf("exactly one of --signature or --tss-url is required; run 'zkprover message' to get the text to sign")
			}

			fmt.Fprintf(os.Stderr, "Claim message: %s\n", target.messageText())

			var (
				params zk.ProofParams
				pubKey *btcec.PublicKey
				err    error
			)
			if signature != "" {
				params, pubKey, err = signatureFromWallet(target, signature)
				if err != nil {
					return fmt.Errorf("invalid wallet signature: %w", err)
				}
			} else {
				fmt.Fprintf(os.Stderr, "Requesting signature from TSS at %s...\n", tssURL)
				params, pubKey, err = signatureFromTSS(target, tssURL)
				if err != nil {
					return err
				}
			}
			if err := zk.CheckPubKeyOwnsAddress(pubKey, target.bitcoinAddress); err != nil {
				return fmt.Errorf("signature was not made by the key of %s: %w", target.bitcoinAddress, err)
			}
			fmt.Fprintln(os.Stderr, "Signature verified against the Bitcoin address")

			pubKeyHashSHA256, err := zk.PubKeyHashSHA256(pubKey.SerializeCompressed())
			if err != nil {
				return err
			}

			prover, err := loadProver(setupDir)
			if err != nil {
				return err
			}

			fmt.Fprintln(os.Stderr, "Generating PLONK proof...")
			proof, err := prover.GenerateProof(params)
			if err != nil {
				return fmt.Errorf("failed to generate proof: %w", err)
			}

			out, err := claimMsgJSON(buildClaimMsg(target, proof, pubKeyHashSHA256))
			if err != nil {
				return fmt.Errorf("failed to serialize claim message: %w", err)
			}
			if outputFile == "" {
				fmt.Println(string(out))
			} else {
				if err := os.WriteFile(outputFile, out, 0o644); err != nil {
					return fmt.Errorf("failed to write output: %w", err)
				}
				fmt.Fprintf(os.Stderr, "Claim message saved to: %s\n", outputFile)
			}
			fmt.Fprintln(os.Stderr, "Submit it with: qbtcd tx qbtc claim-with-proof <file> --from <key>")
			return nil
		},
	}

	addTargetFlags(cmd, &target)
	cmd.Flags().StringArrayVar(&utxoFlags, "utxo", nil, "UTXO to claim as txid:vout (repeatable, at least one)")
	cmd.Flags().StringVar(&signature, "signature", "", "Base64 BIP-137 signature of the claim message from your Bitcoin wallet")
	cmd.Flags().StringVar(&tssURL, "tss-url", "", "URL of a TSS signer API that signs the claim digest (e.g. http://localhost:8080)")
	cmd.Flags().StringVar(&setupDir, "setup-dir", "./zk-setup", "Directory containing setup files")
	cmd.Flags().StringVarP(&outputFile, "output", "o", "", "Output file for the MsgClaimWithProof JSON (defaults to stdout)")

	return cmd
}

// loadProver reads the constraint system and proving key written by 'setup'.
func loadProver(setupDir string) (*zk.Prover, error) {
	csBytes, err := os.ReadFile(filepath.Join(setupDir, "circuit.cs"))
	if err != nil {
		return nil, fmt.Errorf("failed to read constraint system: %w", err)
	}
	cs, err := zk.DeserializeConstraintSystem(csBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to deserialize constraint system: %w", err)
	}
	pkBytes, err := os.ReadFile(filepath.Join(setupDir, "proving.key"))
	if err != nil {
		return nil, fmt.Errorf("failed to read proving key: %w", err)
	}
	pk, err := zk.DeserializeProvingKey(pkBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to deserialize proving key: %w", err)
	}
	return zk.NewProver(cs, pk), nil
}
