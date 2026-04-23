package zk

import (
	"bytes"
	"fmt"
	"sync"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/plonk"
	"github.com/consensys/gnark/frontend"
	"golang.org/x/crypto/ripemd160" //nolint:staticcheck // Bitcoin address hash is defined in terms of RIPEMD160.
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
//
// Beyond the in-circuit checks, the verifier natively enforces:
//  1. params.MessageHash == ComputeClaimMessage(AddressHash, QBTCAddressHash, ChainID)
//  2. RIPEMD160(params.PubKeyHashSHA256) == params.AddressHash
//
// Both (1) and (2) close the binding between the proof's public inputs and
// the 20-byte Bitcoin address being claimed. If (2) is ever skipped, any
// AddressHash would be accepted — see TestBinding_Hash160NativeCheck.
func (v *Verifier) VerifyProof(proof []byte, params VerificationParams) error {
	if len(proof) == 0 {
		return fmt.Errorf("proof cannot be nil")
	}

	// Native check #1: message hash matches the binding tuple.
	expectedMessage := ComputeClaimMessage(params.AddressHash, params.QBTCAddressHash, params.ChainID)
	if expectedMessage != params.MessageHash {
		return fmt.Errorf("message hash mismatch: proof was signed for different parameters")
	}

	// Native check #2: RIPEMD160(SHA256(pubkey)) equals the claimed AddressHash.
	// The circuit binds SHA256(pubkey) to params.PubKeyHashSHA256; this step
	// closes the Hash160 chain to the 20-byte Bitcoin address. Plain equality
	// is fine — both sides are public (on-chain AddressHash and public-input
	// PubKeyHashSHA256), so there is no secret for a timing attacker to learn.
	h := ripemd160.New()
	h.Write(params.PubKeyHashSHA256[:])
	var derivedHash160 [20]byte
	copy(derivedHash160[:], h.Sum(nil))
	if derivedHash160 != params.AddressHash {
		return fmt.Errorf("address hash mismatch: RIPEMD160(PubKeyHashSHA256) does not match AddressHash")
	}

	// Deserialize the proof
	plonkProof := plonk.NewProof(ecc.BN254)
	_, err := plonkProof.ReadFrom(bytes.NewReader(proof))
	if err != nil {
		return fmt.Errorf("failed to deserialize proof: %w", err)
	}

	// Create the public witness with the expected values
	assignment := &BTCPubKeyOwnershipCircuit{}

	for i := range 32 {
		assignment.MessageHash[i] = params.MessageHash[i]
	}
	for i := range 32 {
		assignment.PubKeyHashSHA256[i] = params.PubKeyHashSHA256[i]
	}

	// Create witness from assignment (public only)
	witness, err := frontend.NewWitness(assignment, ecc.BN254.ScalarField(), frontend.PublicOnly())
	if err != nil {
		return fmt.Errorf("failed to create public witness: %w", err)
	}

	if err := plonk.Verify(plonkProof, v.vk, witness); err != nil {
		return fmt.Errorf("proof verification failed: %w", err)
	}

	return nil
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
var ErrVerifierAlreadyInitialized = fmt.Errorf("verifier already initialized - cannot re-initialize VK")

// InitializeVerifier initializes the global verifier from VK bytes.
// This should be called once at node startup.
// Thread-safe: uses mutex for concurrent access.
//
// SECURITY: This function can only be called once per process. Subsequent calls
// will return ErrVerifierAlreadyInitialized. This prevents malicious VK
// replacement attacks.
func InitializeVerifier(vkBytes []byte) error {
	globalState.mu.Lock()
	defer globalState.mu.Unlock()

	// SECURITY: Prevent re-initialization of verifier
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

// InitializeVerifierFromVK initializes the global verifier from a VK object.
// Thread-safe: uses mutex for concurrent access.
//
// SECURITY: This function can only be called once per process. Subsequent calls
// will return ErrVerifierAlreadyInitialized. This prevents malicious VK
// replacement attacks.
func InitializeVerifierFromVK(vk plonk.VerifyingKey) error {
	globalState.mu.Lock()
	defer globalState.mu.Unlock()

	// SECURITY: Prevent re-initialization of verifier
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

// IsVerifierInitialized returns true if the global verifier has been initialized.
// Thread-safe: uses read lock for concurrent access.
func IsVerifierInitialized() bool {
	globalState.mu.RLock()
	defer globalState.mu.RUnlock()
	return globalState.initialized
}

// VerifyProofGlobal verifies a proof using the global verifier.
// Returns an error if the verifier is not initialized.
func VerifyProofGlobal(proof []byte, params VerificationParams) error {
	verifier, err := GetVerifier()
	if err != nil {
		return err
	}
	return verifier.VerifyProof(proof, params)
}

// ClearVerifierForTesting clears the global verifier state.
// WARNING: This is only for testing - DO NOT use in production!
func ClearVerifierForTesting() {
	globalState.mu.Lock()
	defer globalState.mu.Unlock()
	globalState.verifier = nil
	globalState.initialized = false
}
