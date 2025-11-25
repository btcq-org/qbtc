package zk

import (
	"bytes"
	"fmt"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
)

// Verifier handles ZK proof verification
type Verifier struct {
	vk groth16.VerifyingKey
}

// NewVerifier creates a new verifier with the given verifying key
func NewVerifier(vk groth16.VerifyingKey) *Verifier {
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

// VerifyProof verifies a ZK proof for a Bitcoin address claim
func (v *Verifier) VerifyProof(proof *Proof, addressHash [20]byte, btcqAddressHash [32]byte) error {
	// Deserialize the proof
	groth16Proof := groth16.NewProof(ecc.BN254)
	_, err := groth16Proof.ReadFrom(bytes.NewReader(proof.ProofData))
	if err != nil {
		return fmt.Errorf("failed to deserialize proof: %w", err)
	}

	// Create the public witness with the expected values
	assignment := &BTCAddressCircuit{}
	for i := 0; i < 20; i++ {
		assignment.AddressHash[i] = addressHash[i]
	}
	for i := 0; i < 32; i++ {
		assignment.BTCQAddressHash[i] = btcqAddressHash[i]
	}

	// Create witness from assignment (public only)
	witness, err := frontend.NewWitness(assignment, ecc.BN254.ScalarField(), frontend.PublicOnly())
	if err != nil {
		return fmt.Errorf("failed to create public witness: %w", err)
	}

	// Verify the proof
	err = groth16.Verify(groth16Proof, v.vk, witness)
	if err != nil {
		return fmt.Errorf("proof verification failed: %w", err)
	}

	return nil
}

// VerifyProofBytes verifies a proof from raw bytes
func (v *Verifier) VerifyProofBytes(proofBytes []byte, addressHash [20]byte, btcqAddressHash [32]byte) error {
	proof, err := ProofFromProtoZKProof(proofBytes)
	if err != nil {
		return fmt.Errorf("failed to parse proof: %w", err)
	}
	return v.VerifyProof(proof, addressHash, btcqAddressHash)
}

// GetVerifyingKey returns the verifying key
func (v *Verifier) GetVerifyingKey() groth16.VerifyingKey {
	return v.vk
}

// GetVerifyingKeyBytes returns the serialized verifying key
func (v *Verifier) GetVerifyingKeyBytes() ([]byte, error) {
	return SerializeVerifyingKey(v.vk)
}

// VerificationResult represents the result of a proof verification
type VerificationResult struct {
	Valid   bool
	Error   error
	Details string
}

// VerifyProofWithDetails verifies a proof and returns detailed results
func (v *Verifier) VerifyProofWithDetails(proof *Proof, addressHash [20]byte, btcqAddressHash [32]byte) VerificationResult {
	err := v.VerifyProof(proof, addressHash, btcqAddressHash)
	if err != nil {
		return VerificationResult{
			Valid:   false,
			Error:   err,
			Details: err.Error(),
		}
	}
	return VerificationResult{
		Valid:   true,
		Details: "Proof verified successfully",
	}
}

// DefaultVerifier holds a pre-configured verifier with the embedded verification key
// This is set during module initialization
var DefaultVerifier *Verifier

// InitDefaultVerifier initializes the default verifier with the embedded key
func InitDefaultVerifier(vkBytes []byte) error {
	var err error
	DefaultVerifier, err = NewVerifierFromBytes(vkBytes)
	return err
}

// VerifyWithDefault verifies a proof using the default verifier
func VerifyWithDefault(proof *Proof, addressHash [20]byte, btcqAddressHash [32]byte) error {
	if DefaultVerifier == nil {
		return fmt.Errorf("default verifier not initialized")
	}
	return DefaultVerifier.VerifyProof(proof, addressHash, btcqAddressHash)
}
