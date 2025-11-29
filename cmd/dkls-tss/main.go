// Package main provides a DKLS TSS (Threshold Signature Scheme) integration
// with the ZK proof system. This demonstrates using the real DKLS library
// for distributed key generation and signing with zero-knowledge proofs.
package main

import (
	"fmt"
	"log"
	"math/big"
	"os"
	"strings"

	"github.com/btcq-org/qbtc/x/qbtc/zk"
	"github.com/ethereum/go-ethereum/crypto/secp256k1"
	session "github.com/vultisig/go-wrappers/go-dkls/sessions"
)

// Participant represents a party in the TSS protocol
type Participant struct {
	Session session.Handle
	ID      string
}

// prepareIDSlice creates participant IDs for the TSS protocol
func prepareIDSlice(n int) []byte {
	keys := make([]string, n)
	for p := 1; p <= n; p++ {
		keys[p-1] = fmt.Sprintf("p%d", p)
	}
	return []byte(strings.Join(keys, "\x00"))
}

// runKeygen performs distributed key generation for n parties with threshold t
func runKeygen(t, n int) ([]session.Handle, error) {
	ids := prepareIDSlice(n)

	setupMsg, err := session.DklsKeygenSetupMsgNew(t, nil, ids)
	if err != nil {
		return nil, fmt.Errorf("failed to create keygen setup: %w", err)
	}

	parties := make([]Participant, n)
	for i := 1; i <= n; i++ {
		id := fmt.Sprintf("p%d", i)
		sessionHandle, err := session.DklsKeygenSessionFromSetup(setupMsg, []byte(id))
		if err != nil {
			return nil, fmt.Errorf("failed to create keygen session for %s: %w", id, err)
		}
		parties[i-1] = Participant{Session: sessionHandle, ID: id}
	}

	return runKeygenLoop(parties)
}

// runKeygenLoop runs the message passing loop for keygen
func runKeygenLoop(parties []Participant) ([]session.Handle, error) {
	msgq := make(map[string][][]byte)
	n := len(parties)
	shares := make([]session.Handle, 0, n)

	for len(shares) != n {
		// Output messages from all parties
		for _, party := range parties {
			for {
				buf, err := session.DklsKeygenSessionOutputMessage(party.Session)
				if err != nil {
					return nil, fmt.Errorf("keygen output error for %s: %w", party.ID, err)
				}
				if buf == nil {
					break
				}

				// Route message to receivers
				for idx := 0; idx < n; idx++ {
					receiver, err := session.DklsKeygenSessionMessageReceiver(party.Session, buf, idx)
					if err != nil {
						return nil, fmt.Errorf("keygen receiver error: %w", err)
					}
					if receiver == "" {
						break
					}
					msgq[receiver] = append(msgq[receiver], buf)
				}
			}
		}

		// Input messages to all parties
		for _, party := range parties {
			for _, msg := range msgq[party.ID] {
				finished, err := session.DklsKeygenSessionInputMessage(party.Session, msg)
				if err != nil {
					return nil, fmt.Errorf("keygen input error for %s: %w", party.ID, err)
				}
				if finished {
					share, err := session.DklsKeygenSessionFinish(party.Session)
					if err != nil {
						return nil, fmt.Errorf("keygen finish error for %s: %w", party.ID, err)
					}
					shares = append(shares, share)
					_ = session.DklsKeygenSessionFree(party.Session)
				}
			}
			msgq[party.ID] = nil
		}
	}

	return shares, nil
}

// runSign performs distributed signing with the given keyshares
func runSign(shares []session.Handle, msg []byte) ([][]byte, error) {
	t := len(shares)

	keyID, err := session.DklsKeyshareKeyID(shares[0])
	if err != nil {
		return nil, fmt.Errorf("failed to get key ID: %w", err)
	}

	ids := prepareIDSlice(t)
	setup, err := session.DklsSignSetupMsgNew(keyID, nil, msg, ids)
	if err != nil {
		return nil, fmt.Errorf("failed to create sign setup: %w", err)
	}

	parties := make([]Participant, t)
	for i := 1; i <= t; i++ {
		id := fmt.Sprintf("p%d", i)
		sessionHandle, err := session.DklsSignSessionFromSetup(setup, []byte(id), shares[i-1])
		if err != nil {
			return nil, fmt.Errorf("failed to create sign session for %s: %w", id, err)
		}
		parties[i-1] = Participant{Session: sessionHandle, ID: id}
	}

	return runSignLoop(parties)
}

// runSignLoop runs the message passing loop for signing
func runSignLoop(parties []Participant) ([][]byte, error) {
	msgq := make(map[string][][]byte)
	t := len(parties)
	signatures := make([][]byte, 0, t)

	for len(signatures) != t {
		// Output messages from all parties
		for _, party := range parties {
			for {
				buf, err := session.DklsSignSessionOutputMessage(party.Session)
				if err != nil {
					return nil, fmt.Errorf("sign output error for %s: %w", party.ID, err)
				}
				if len(buf) == 0 {
					break
				}

				// Route message to receivers
				for idx := 0; idx < t; idx++ {
					receiver, err := session.DklsSignSessionMessageReceiver(party.Session, buf, idx)
					if err != nil {
						return nil, fmt.Errorf("sign receiver error: %w", err)
					}
					if len(receiver) == 0 {
						break
					}
					msgq[string(receiver)] = append(msgq[string(receiver)], buf)
				}
			}
		}

		// Input messages to all parties
		for _, party := range parties {
			for _, msg := range msgq[party.ID] {
				finished, err := session.DklsSignSessionInputMessage(party.Session, msg)
				if err != nil {
					return nil, fmt.Errorf("sign input error for %s: %w", party.ID, err)
				}
				if finished {
					sig, err := session.DklsSignSessionFinish(party.Session)
					if err != nil {
						return nil, fmt.Errorf("sign finish error for %s: %w", party.ID, err)
					}
					signatures = append(signatures, sig)
					_ = session.DklsSignSessionFree(party.Session)
				}
			}
			msgq[party.ID] = nil
		}
	}

	return signatures, nil
}

func main() {
	fmt.Println("=== DKLS TSS + ZK Proof Integration Demo ===")
	fmt.Println()

	// Step 1: Run 2-of-2 DKLS keygen
	fmt.Println("Step 1: Running 2-of-2 DKLS distributed key generation...")
	keyshares, err := runKeygen(2, 2)
	if err != nil {
		log.Fatalf("Keygen failed: %v", err)
	}
	fmt.Printf("  ✓ Generated %d keyshares\n", len(keyshares))

	// Get the shared public key
	pubKeyBytes, err := session.DklsKeysharePublicKey(keyshares[0])
	if err != nil {
		log.Fatalf("Failed to get public key: %v", err)
	}
	fmt.Printf("  ✓ Shared public key (compressed): %x\n", pubKeyBytes)

	// Step 2: Compute address hash from TSS public key
	fmt.Println("\nStep 2: Computing Bitcoin address hash from TSS public key...")
	addressHash, err := zk.PublicKeyToAddressHash(pubKeyBytes)
	if err != nil {
		log.Fatalf("Failed to compute address hash: %v", err)
	}
	fmt.Printf("  ✓ Bitcoin address hash (Hash160): %x\n", addressHash)

	// Step 3: Prepare claim parameters
	fmt.Println("\nStep 3: Preparing claim parameters...")
	claimerAddress := "qbtc1dklstss_demo_claimer"
	chainID := "qbtc-mainnet-1"
	btcqAddressHash := zk.HashBTCQAddress(claimerAddress)
	chainIDHash := zk.ComputeChainIDHash(chainID)
	fmt.Printf("  ✓ Claimer address: %s\n", claimerAddress)
	fmt.Printf("  ✓ Chain ID: %s\n", chainID)

	// Compute the claim message (this is what TSS signs)
	messageHash := zk.ComputeClaimMessage(addressHash, btcqAddressHash, chainIDHash)
	fmt.Printf("  ✓ Message hash to sign: %x\n", messageHash)

	// Step 4: Sign with TSS
	fmt.Println("\nStep 4: Signing claim message with 2-of-2 TSS...")
	signatures, err := runSign(keyshares, messageHash[:])
	if err != nil {
		log.Fatalf("Signing failed: %v", err)
	}
	// All parties produce the same signature, use the first one
	sig := signatures[0]
	fmt.Printf("  ✓ Signature (R||S||V): %x\n", sig)

	// Parse R, S from signature (format: R[32] || S[32] || V[1])
	if len(sig) != 65 {
		log.Fatalf("Unexpected signature length: got %d, expected 65", len(sig))
	}
	sigR := new(big.Int).SetBytes(sig[:32])
	sigS := new(big.Int).SetBytes(sig[32:64])
	fmt.Printf("  ✓ R: %s\n", sigR.Text(16))
	fmt.Printf("  ✓ S: %s\n", sigS.Text(16))

	// Decompress public key to get X, Y coordinates
	pubKeyX, pubKeyY := secp256k1.DecompressPubkey(pubKeyBytes)
	if pubKeyX == nil {
		log.Fatal("Failed to decompress public key")
	}
	fmt.Printf("  ✓ Public key X: %s\n", pubKeyX.Text(16))
	fmt.Printf("  ✓ Public key Y: %s\n", pubKeyY.Text(16))

	// Step 5: Generate ZK proof
	fmt.Println("\nStep 5: Setting up ZK prover and generating proof...")
	fmt.Println("  (This may take a while for PLONK setup...)")

	// Setup PLONK (using test options for faster setup)
	setup, err := zk.SetupWithOptions(zk.TestSetupOptions())
	if err != nil {
		log.Fatalf("PLONK setup failed: %v", err)
	}
	fmt.Println("  ✓ PLONK setup complete")

	// Register verifier
	vkBytes, err := zk.SerializeVerifyingKey(setup.VerifyingKey)
	if err != nil {
		log.Fatalf("Failed to serialize VK: %v", err)
	}
	if err := zk.RegisterVerifier(vkBytes); err != nil {
		log.Fatalf("Failed to register verifier: %v", err)
	}
	fmt.Println("  ✓ Verifier registered")

	// Create prover and generate proof
	prover := zk.ProverFromSetup(setup)
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
		log.Fatalf("Proof generation failed: %v", err)
	}
	fmt.Printf("  ✓ Proof generated (%d bytes)\n", len(proof))

	// Step 6: Verify proof
	fmt.Println("\nStep 6: Verifying ZK proof...")
	err = zk.VerifyProofGlobal(proof, zk.VerificationParams{
		MessageHash:     messageHash,
		AddressHash:     addressHash,
		QBTCAddressHash: btcqAddressHash,
		ChainID:         chainIDHash,
	})
	if err != nil {
		log.Fatalf("Proof verification failed: %v", err)
	}
	fmt.Println("  ✓ Proof verified successfully!")

	fmt.Println("\n=== Demo Complete ===")
	fmt.Println("Successfully demonstrated:")
	fmt.Println("  1. 2-of-2 DKLS distributed key generation")
	fmt.Println("  2. TSS signing of ZK claim message")
	fmt.Println("  3. ZK proof generation with TSS signature")
	fmt.Println("  4. ZK proof verification")

	// Cleanup keyshares
	for _, share := range keyshares {
		_ = session.DklsKeyshareFree(share)
	}

	os.Exit(0)
}
