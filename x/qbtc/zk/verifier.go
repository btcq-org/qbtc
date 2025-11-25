package zk

import (
	"bytes"
	"fmt"
	"sync"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/plonk"
	"github.com/consensys/gnark/frontend"
)

// Verifier handles ZK proof verification for signature-based proofs using PLONK.
// This verifier is TSS/MPC compatible - it verifies proofs of ECDSA signature validity.
type Verifier struct {
	vk plonk.VerifyingKey
}

// NewVerifier creates a new verifier with the given verifying key
func NewVerifier(vk plonk.VerifyingKey) *Verifier {
	return &Verifier{vk: vk}
}

// NewVerifierFromBytes creates a verifier from serialized verifying key bytes
func NewVerifierFromBytes(vkBytes []byte) (*Verifier, error) {
	vk, err := DeserializeVerifyingKey(vkBytes)
	if err != nil {
		return nil, err
	}
	return &Verifier{vk: vk}, nil
}

// VerifyProof verifies a PLONK proof for a signature-based Bitcoin address claim.
// It checks that:
// 1. The proof is valid
// 2. The message hash matches the expected value (computed from the claim parameters)
func (v *Verifier) VerifyProof(proof *Proof, params VerificationParams) error {
	if proof == nil {
		return fmt.Errorf("proof cannot be nil")
	}

	// Verify the message hash matches expected
	expectedMessage := ComputeClaimMessage(params.AddressHash, params.BTCQAddressHash, params.ChainID)
	if expectedMessage != params.MessageHash {
		return fmt.Errorf("message hash mismatch: proof was signed for different parameters")
	}

	// Deserialize the proof
	plonkProof := plonk.NewProof(ecc.BN254)
	_, err := plonkProof.ReadFrom(bytes.NewReader(proof.ProofData))
	if err != nil {
		return fmt.Errorf("failed to deserialize proof: %w", err)
	}

	// Create the public witness with the expected values
	assignment := &BTCSignatureCircuit{}

	// Set message hash
	for i := 0; i < 32; i++ {
		assignment.MessageHash[i] = params.MessageHash[i]
	}

	// Set address hash
	for i := 0; i < 20; i++ {
		assignment.AddressHash[i] = params.AddressHash[i]
	}

	// Set BTCQ address hash
	for i := 0; i < 32; i++ {
		assignment.BTCQAddressHash[i] = params.BTCQAddressHash[i]
	}

	// Set chain ID
	for i := 0; i < 8; i++ {
		assignment.ChainID[i] = params.ChainID[i]
	}

	// Create witness from assignment (public only)
	witness, err := frontend.NewWitness(assignment, ecc.BN254.ScalarField(), frontend.PublicOnly())
	if err != nil {
		return fmt.Errorf("failed to create public witness: %w", err)
	}

	// Verify the proof
	err = plonk.Verify(plonkProof, v.vk, witness)
	if err != nil {
		return fmt.Errorf("proof verification failed: %w", err)
	}

	return nil
}

// GetVerifyingKey returns the verifying key
func (v *Verifier) GetVerifyingKey() plonk.VerifyingKey {
	return v.vk
}

// GetVerifyingKeyBytes returns the serialized verifying key
func (v *Verifier) GetVerifyingKeyBytes() ([]byte, error) {
	return SerializeVerifyingKey(v.vk)
}

// globalVerifierState holds the global verifier state with thread-safe access.
// SECURITY: Once initialized, the verifier is immutable to prevent VK replacement attacks.
type globalVerifierState struct {
	mu          sync.RWMutex
	verifier    *Verifier
	initialized bool // once true, verifier cannot be changed
}

// globalState is the singleton verifier state instance.
var globalState = &globalVerifierState{}

// ErrVerifierAlreadyInitialized is returned when attempting to re-register the verifier.
var ErrVerifierAlreadyInitialized = fmt.Errorf("verifier already initialized - cannot re-register VK")

// RegisterVerifier registers the global verifier from VK bytes.
// This should be called once at node startup from genesis.
// Thread-safe: uses mutex for concurrent access.
//
// SECURITY: This function can only be called once. Subsequent calls will return
// ErrVerifierAlreadyInitialized. This prevents malicious VK replacement attacks.
func RegisterVerifier(vkBytes []byte) error {
	globalState.mu.Lock()
	defer globalState.mu.Unlock()

	// SECURITY: Prevent re-registration of verifier
	if globalState.initialized {
		return ErrVerifierAlreadyInitialized
	}

	verifier, err := NewVerifierFromBytes(vkBytes)
	if err != nil {
		return fmt.Errorf("failed to create verifier: %w", err)
	}

	globalState.verifier = verifier
	globalState.initialized = true
	return nil
}

// RegisterVerifierFromVK registers the global verifier from a VK object.
// Thread-safe: uses mutex for concurrent access.
//
// SECURITY: This function can only be called once. Subsequent calls will return
// ErrVerifierAlreadyInitialized. This prevents malicious VK replacement attacks.
func RegisterVerifierFromVK(vk plonk.VerifyingKey) error {
	globalState.mu.Lock()
	defer globalState.mu.Unlock()

	// SECURITY: Prevent re-registration of verifier
	if globalState.initialized {
		return ErrVerifierAlreadyInitialized
	}

	globalState.verifier = NewVerifier(vk)
	globalState.initialized = true
	return nil
}

// GetVerifier returns the global verifier.
// Thread-safe: uses read lock for concurrent access.
func GetVerifier() (*Verifier, error) {
	globalState.mu.RLock()
	defer globalState.mu.RUnlock()

	if globalState.verifier == nil {
		return nil, fmt.Errorf("verifier not initialized - VK not loaded from genesis")
	}
	return globalState.verifier, nil
}

// IsVerifierInitialized returns true if the global verifier has been registered.
// Thread-safe: uses read lock for concurrent access.
func IsVerifierInitialized() bool {
	globalState.mu.RLock()
	defer globalState.mu.RUnlock()
	return globalState.initialized
}

// VerifyProofGlobal verifies a proof using the global verifier.
// Returns an error if the verifier is not initialized.
func VerifyProofGlobal(proof *Proof, params VerificationParams) error {
	verifier, err := GetVerifier()
	if err != nil {
		return err
	}
	return verifier.VerifyProof(proof, params)
}
