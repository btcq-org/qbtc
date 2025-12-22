// Package zk implements zero-knowledge proof generation and verification.
package zk

import (
	"bytes"
	"fmt"
	"sync"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/plonk"
	"github.com/consensys/gnark/frontend"
)

// CircuitType identifies the type of ZK circuit being used
type CircuitType int

const (
	// CircuitTypeECDSA is the standard P2PKH/P2WPKH circuit (ECDSA + Hash160)
	CircuitTypeECDSA CircuitType = iota
	// CircuitTypeSchnorr is the Taproot circuit (Schnorr signature)
	CircuitTypeSchnorr
	// CircuitTypeP2SHP2WPKH is the P2SH-wrapped P2WPKH circuit
	CircuitTypeP2SHP2WPKH
	// CircuitTypeP2PK is the legacy P2PK circuit (ECDSA, no Hash160)
	CircuitTypeP2PK
	// CircuitTypeP2WSHSingleKey is the P2WSH circuit for single-key scripts
	CircuitTypeP2WSHSingleKey
)

// String returns a human-readable name for the circuit type
func (t CircuitType) String() string {
	switch t {
	case CircuitTypeECDSA:
		return "ECDSA"
	case CircuitTypeSchnorr:
		return "Schnorr"
	case CircuitTypeP2SHP2WPKH:
		return "P2SH-P2WPKH"
	case CircuitTypeP2PK:
		return "P2PK"
	case CircuitTypeP2WSHSingleKey:
		return "P2WSH-SingleKey"
	default:
		return "Unknown"
	}
}

// CircuitTypeForAddressType returns the appropriate circuit type for a given address type
func CircuitTypeForAddressType(addrType AddressType) (CircuitType, error) {
	switch addrType {
	case AddressTypeP2PKH, AddressTypeP2WPKH:
		return CircuitTypeECDSA, nil
	case AddressTypeP2TR:
		return CircuitTypeSchnorr, nil
	case AddressTypeP2SH:
		// Note: P2SH could wrap different scripts; we assume P2SH-P2WPKH here
		return CircuitTypeP2SHP2WPKH, nil
	case AddressTypeP2PK:
		return CircuitTypeP2PK, nil
	case AddressTypeP2WSH:
		return CircuitTypeP2WSHSingleKey, nil
	default:
		return CircuitTypeECDSA, fmt.Errorf("unsupported address type: %s", addrType)
	}
}

// MultiVerifier handles verification of proofs for multiple circuit types
type MultiVerifier struct {
	verifiers map[CircuitType]*Verifier
	mu        sync.RWMutex
}

// NewMultiVerifier creates a new multi-circuit verifier
func NewMultiVerifier() *MultiVerifier {
	return &MultiVerifier{
		verifiers: make(map[CircuitType]*Verifier),
	}
}

// RegisterCircuit registers a verifying key for a specific circuit type
func (mv *MultiVerifier) RegisterCircuit(circuitType CircuitType, vk plonk.VerifyingKey) {
	mv.mu.Lock()
	defer mv.mu.Unlock()
	mv.verifiers[circuitType] = NewVerifier(vk)
}

// RegisterCircuitFromBytes registers a verifying key from bytes for a specific circuit type
func (mv *MultiVerifier) RegisterCircuitFromBytes(circuitType CircuitType, vkBytes []byte) error {
	vk, err := DeserializeVerifyingKey(vkBytes)
	if err != nil {
		return fmt.Errorf("failed to deserialize VK for %s: %w", circuitType, err)
	}
	mv.RegisterCircuit(circuitType, vk)
	return nil
}

// HasCircuit returns true if the verifier has a VK registered for the given circuit type
func (mv *MultiVerifier) HasCircuit(circuitType CircuitType) bool {
	mv.mu.RLock()
	defer mv.mu.RUnlock()
	_, ok := mv.verifiers[circuitType]
	return ok
}

// VerifyECDSAProof verifies a P2PKH/P2WPKH proof
func (mv *MultiVerifier) VerifyECDSAProof(proof *Proof, params VerificationParams) error {
	mv.mu.RLock()
	verifier, ok := mv.verifiers[CircuitTypeECDSA]
	mv.mu.RUnlock()

	if !ok {
		return fmt.Errorf("ecdsa circuit not registered")
	}
	return verifier.VerifyProof(proof, params)
}

// VerifySchnorrProof verifies a Taproot proof
func (mv *MultiVerifier) VerifySchnorrProof(proof *Proof, params SchnorrVerificationParams) error {
	mv.mu.RLock()
	verifier, ok := mv.verifiers[CircuitTypeSchnorr]
	mv.mu.RUnlock()

	if !ok {
		return fmt.Errorf("schnorr circuit not registered")
	}

	if proof == nil || proof.ProofData == nil {
		return fmt.Errorf("proof cannot be nil")
	}

	// Verify the message hash matches expected
	expectedMessage := ComputeClaimMessageForSchnorr(params.XOnlyPubKey, params.BTCQAddressHash, params.ChainID)
	if expectedMessage != params.MessageHash {
		return fmt.Errorf("message hash mismatch: proof was signed for different parameters")
	}

	// Deserialize the proof
	plonkProof := plonk.NewProof(ecc.BN254)
	_, err := plonkProof.ReadFrom(bytes.NewReader(proof.ProofData))
	if err != nil {
		return fmt.Errorf("failed to deserialize proof: %w", err)
	}

	// Create the public witness
	assignment := &BTCSchnorrCircuit{}
	for i := 0; i < 32; i++ {
		assignment.MessageHash[i] = params.MessageHash[i]
		assignment.XOnlyPubKey[i] = params.XOnlyPubKey[i]
		assignment.BTCQAddressHash[i] = params.BTCQAddressHash[i]
	}
	for i := 0; i < 8; i++ {
		assignment.ChainID[i] = params.ChainID[i]
	}

	witness, err := frontend.NewWitness(assignment, ecc.BN254.ScalarField(), frontend.PublicOnly())
	if err != nil {
		return fmt.Errorf("failed to create public witness: %w", err)
	}

	return plonk.Verify(plonkProof, verifier.vk, witness)
}

// VerifyP2SHP2WPKHProof verifies a P2SH-wrapped P2WPKH proof
func (mv *MultiVerifier) VerifyP2SHP2WPKHProof(proof *Proof, params P2SHP2WPKHVerificationParams) error {
	mv.mu.RLock()
	verifier, ok := mv.verifiers[CircuitTypeP2SHP2WPKH]
	mv.mu.RUnlock()

	if !ok {
		return fmt.Errorf("p2sh-p2wpkh circuit not registered")
	}

	if proof == nil || proof.ProofData == nil {
		return fmt.Errorf("proof cannot be nil")
	}

	// Verify the message hash matches expected
	expectedMessage := ComputeClaimMessageForP2SH(params.ScriptHash, params.BTCQAddressHash, params.ChainID)
	if expectedMessage != params.MessageHash {
		return fmt.Errorf("message hash mismatch: proof was signed for different parameters")
	}

	// Deserialize the proof
	plonkProof := plonk.NewProof(ecc.BN254)
	_, err := plonkProof.ReadFrom(bytes.NewReader(proof.ProofData))
	if err != nil {
		return fmt.Errorf("failed to deserialize proof: %w", err)
	}

	// Create the public witness
	assignment := &BTCP2SHP2WPKHCircuit{}
	for i := 0; i < 32; i++ {
		assignment.MessageHash[i] = params.MessageHash[i]
		assignment.BTCQAddressHash[i] = params.BTCQAddressHash[i]
	}
	for i := 0; i < 20; i++ {
		assignment.ScriptHash[i] = params.ScriptHash[i]
	}
	for i := 0; i < 8; i++ {
		assignment.ChainID[i] = params.ChainID[i]
	}

	witness, err := frontend.NewWitness(assignment, ecc.BN254.ScalarField(), frontend.PublicOnly())
	if err != nil {
		return fmt.Errorf("failed to create public witness: %w", err)
	}

	return plonk.Verify(plonkProof, verifier.vk, witness)
}

// VerifyP2PKProof verifies a P2PK proof
func (mv *MultiVerifier) VerifyP2PKProof(proof *Proof, params P2PKVerificationParams) error {
	mv.mu.RLock()
	verifier, ok := mv.verifiers[CircuitTypeP2PK]
	mv.mu.RUnlock()

	if !ok {
		return fmt.Errorf("p2pk circuit not registered")
	}

	if proof == nil || proof.ProofData == nil {
		return fmt.Errorf("proof cannot be nil")
	}

	// Verify the message hash matches expected
	expectedMessage := ComputeClaimMessageForP2PK(params.CompressedPubKey, params.BTCQAddressHash, params.ChainID)
	if expectedMessage != params.MessageHash {
		return fmt.Errorf("message hash mismatch: proof was signed for different parameters")
	}

	// Deserialize the proof
	plonkProof := plonk.NewProof(ecc.BN254)
	_, err := plonkProof.ReadFrom(bytes.NewReader(proof.ProofData))
	if err != nil {
		return fmt.Errorf("failed to deserialize proof: %w", err)
	}

	// Create the public witness
	assignment := &BTCP2PKCircuit{}
	for i := 0; i < 32; i++ {
		assignment.MessageHash[i] = params.MessageHash[i]
		assignment.BTCQAddressHash[i] = params.BTCQAddressHash[i]
	}
	for i := 0; i < 33; i++ {
		assignment.CompressedPubKey[i] = params.CompressedPubKey[i]
	}
	for i := 0; i < 8; i++ {
		assignment.ChainID[i] = params.ChainID[i]
	}

	witness, err := frontend.NewWitness(assignment, ecc.BN254.ScalarField(), frontend.PublicOnly())
	if err != nil {
		return fmt.Errorf("failed to create public witness: %w", err)
	}

	return plonk.Verify(plonkProof, verifier.vk, witness)
}

// VerifyP2WSHSingleKeyProof verifies a P2WSH single-key proof
func (mv *MultiVerifier) VerifyP2WSHSingleKeyProof(proof *Proof, params P2WSHSingleKeyVerificationParams) error {
	mv.mu.RLock()
	verifier, ok := mv.verifiers[CircuitTypeP2WSHSingleKey]
	mv.mu.RUnlock()

	if !ok {
		return fmt.Errorf("p2wsh-singlekey circuit not registered")
	}

	if proof == nil || proof.ProofData == nil {
		return fmt.Errorf("proof cannot be nil")
	}

	// Verify the message hash matches expected
	expectedMessage := ComputeClaimMessageForP2WSH(params.WitnessProgram, params.BTCQAddressHash, params.ChainID)
	if expectedMessage != params.MessageHash {
		return fmt.Errorf("message hash mismatch: proof was signed for different parameters")
	}

	// Deserialize the proof
	plonkProof := plonk.NewProof(ecc.BN254)
	_, err := plonkProof.ReadFrom(bytes.NewReader(proof.ProofData))
	if err != nil {
		return fmt.Errorf("failed to deserialize proof: %w", err)
	}

	// Create the public witness
	assignment := &BTCP2WSHSingleKeyCircuit{}
	for i := 0; i < 32; i++ {
		assignment.MessageHash[i] = params.MessageHash[i]
		assignment.WitnessProgram[i] = params.WitnessProgram[i]
		assignment.BTCQAddressHash[i] = params.BTCQAddressHash[i]
	}
	for i := 0; i < 8; i++ {
		assignment.ChainID[i] = params.ChainID[i]
	}

	witness, err := frontend.NewWitness(assignment, ecc.BN254.ScalarField(), frontend.PublicOnly())
	if err != nil {
		return fmt.Errorf("failed to create public witness: %w", err)
	}

	return plonk.Verify(plonkProof, verifier.vk, witness)
}

// globalMultiVerifierState holds the global multi-verifier state
type globalMultiVerifierState struct {
	mu          sync.RWMutex
	verifier    *MultiVerifier
	initialized bool
}

var globalMultiState = &globalMultiVerifierState{}

// RegisterMultiVerifier registers the global multi-verifier.
// SECURITY: Once initialized, no new circuits can be added.
func RegisterMultiVerifier(mv *MultiVerifier) error {
	globalMultiState.mu.Lock()
	defer globalMultiState.mu.Unlock()

	if globalMultiState.initialized {
		return ErrVerifierAlreadyInitialized
	}

	globalMultiState.verifier = mv
	globalMultiState.initialized = true
	return nil
}

// GetMultiVerifier returns the global multi-verifier
func GetMultiVerifier() (*MultiVerifier, error) {
	globalMultiState.mu.RLock()
	defer globalMultiState.mu.RUnlock()

	if globalMultiState.verifier == nil {
		return nil, fmt.Errorf("multi-verifier not initialized")
	}
	return globalMultiState.verifier, nil
}

// IsMultiVerifierInitialized returns true if the global multi-verifier is initialized
func IsMultiVerifierInitialized() bool {
	globalMultiState.mu.RLock()
	defer globalMultiState.mu.RUnlock()
	return globalMultiState.initialized
}
