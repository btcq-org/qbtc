package zk

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"io"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
)

// SetupResult contains the compiled circuit and keys from trusted setup
type SetupResult struct {
	ConstraintSystem constraint.ConstraintSystem
	ProvingKey       groth16.ProvingKey
	VerifyingKey     groth16.VerifyingKey
}

// Setup performs the trusted setup for the BTCAddressCircuit
// This generates the proving and verifying keys
func Setup() (*SetupResult, error) {
	// Create a placeholder circuit for compilation
	var circuit BTCAddressCircuit

	// Compile the circuit to R1CS
	cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit)
	if err != nil {
		return nil, fmt.Errorf("failed to compile circuit: %w", err)
	}

	// Run the trusted setup (Groth16)
	pk, vk, err := groth16.Setup(cs)
	if err != nil {
		return nil, fmt.Errorf("failed to run setup: %w", err)
	}

	return &SetupResult{
		ConstraintSystem: cs,
		ProvingKey:       pk,
		VerifyingKey:     vk,
	}, nil
}

// SerializeVerifyingKey serializes the verifying key to bytes
func SerializeVerifyingKey(vk groth16.VerifyingKey) ([]byte, error) {
	var buf bytes.Buffer
	_, err := vk.WriteTo(&buf)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize verifying key: %w", err)
	}
	return buf.Bytes(), nil
}

// DeserializeVerifyingKey deserializes a verifying key from bytes
func DeserializeVerifyingKey(data []byte) (groth16.VerifyingKey, error) {
	vk := groth16.NewVerifyingKey(ecc.BN254)
	_, err := vk.ReadFrom(bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("failed to deserialize verifying key: %w", err)
	}
	return vk, nil
}

// SerializeProvingKey serializes the proving key to bytes
func SerializeProvingKey(pk groth16.ProvingKey) ([]byte, error) {
	var buf bytes.Buffer
	_, err := pk.WriteTo(&buf)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize proving key: %w", err)
	}
	return buf.Bytes(), nil
}

// DeserializeProvingKey deserializes a proving key from bytes
func DeserializeProvingKey(data []byte) (groth16.ProvingKey, error) {
	pk := groth16.NewProvingKey(ecc.BN254)
	_, err := pk.ReadFrom(bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("failed to deserialize proving key: %w", err)
	}
	return pk, nil
}

// SerializeConstraintSystem serializes the constraint system to bytes
func SerializeConstraintSystem(cs constraint.ConstraintSystem) ([]byte, error) {
	var buf bytes.Buffer
	_, err := cs.WriteTo(&buf)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize constraint system: %w", err)
	}
	return buf.Bytes(), nil
}

// DeserializeConstraintSystem deserializes a constraint system from bytes
func DeserializeConstraintSystem(data []byte) (constraint.ConstraintSystem, error) {
	cs := groth16.NewCS(ecc.BN254)
	_, err := cs.ReadFrom(bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("failed to deserialize constraint system: %w", err)
	}
	return cs, nil
}

// Prover handles proof generation
type Prover struct {
	cs constraint.ConstraintSystem
	pk groth16.ProvingKey
}

// NewProver creates a new prover with the given constraint system and proving key
func NewProver(cs constraint.ConstraintSystem, pk groth16.ProvingKey) *Prover {
	return &Prover{cs: cs, pk: pk}
}

// ProverFromSetup creates a prover from setup result
func ProverFromSetup(setup *SetupResult) *Prover {
	return NewProver(setup.ConstraintSystem, setup.ProvingKey)
}

// GenerateProof generates a ZK proof that proves ownership of the Bitcoin address
// corresponding to the given private key
func (p *Prover) GenerateProof(privateKey *big.Int, addressHash [20]byte, btcqAddressHash [32]byte) (*Proof, error) {
	// Create witness assignment
	assignment := &BTCAddressCircuit{}

	// Set the private key (as emulated field element)
	// The emulated element will be set during witness creation
	assignment.PrivateKey.Limbs = make([]frontend.Variable, 4)
	// Convert big.Int to 4 limbs of 64 bits each
	pkBytes := privateKey.Bytes()
	// Pad to 32 bytes
	padded := make([]byte, 32)
	copy(padded[32-len(pkBytes):], pkBytes)

	// Convert to limbs (little-endian limb order, big-endian within limb)
	for i := 0; i < 4; i++ {
		limb := new(big.Int)
		limbBytes := padded[24-i*8 : 32-i*8]
		limb.SetBytes(limbBytes)
		assignment.PrivateKey.Limbs[i] = limb
	}

	// Set the address hash (public input)
	for i := 0; i < 20; i++ {
		assignment.AddressHash[i] = addressHash[i]
	}

	// Set the BTCQ address hash (public input for binding)
	for i := 0; i < 32; i++ {
		assignment.BTCQAddressHash[i] = btcqAddressHash[i]
	}

	// Create the full witness
	witness, err := frontend.NewWitness(assignment, ecc.BN254.ScalarField())
	if err != nil {
		return nil, fmt.Errorf("failed to create witness: %w", err)
	}

	// Generate the proof
	proof, err := groth16.Prove(p.cs, p.pk, witness)
	if err != nil {
		return nil, fmt.Errorf("failed to generate proof: %w", err)
	}

	// Serialize the proof
	var proofBuf bytes.Buffer
	_, err = proof.WriteTo(&proofBuf)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize proof: %w", err)
	}

	// Get public witness
	publicWitness, err := witness.Public()
	if err != nil {
		return nil, fmt.Errorf("failed to get public witness: %w", err)
	}

	// Serialize public inputs
	var publicBuf bytes.Buffer
	_, err = publicWitness.WriteTo(&publicBuf)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize public inputs: %w", err)
	}

	return &Proof{
		ProofData:    proofBuf.Bytes(),
		PublicInputs: publicBuf.Bytes(),
	}, nil
}

// Proof contains the serialized ZK proof and public inputs
type Proof struct {
	ProofData    []byte
	PublicInputs []byte
}

// ToProtoZKProof converts the proof to the protobuf ZKProof type
func (p *Proof) ToProtoZKProof() []byte {
	// Combine proof data and public inputs
	// Format: [4 bytes proof length][proof data][public inputs]
	proofLen := uint32(len(p.ProofData))
	result := make([]byte, 4+len(p.ProofData)+len(p.PublicInputs))
	result[0] = byte(proofLen >> 24)
	result[1] = byte(proofLen >> 16)
	result[2] = byte(proofLen >> 8)
	result[3] = byte(proofLen)
	copy(result[4:], p.ProofData)
	copy(result[4+len(p.ProofData):], p.PublicInputs)
	return result
}

// ProofFromProtoZKProof parses a proof from the protobuf ZKProof format
func ProofFromProtoZKProof(data []byte) (*Proof, error) {
	if len(data) < 4 {
		return nil, fmt.Errorf("proof data too short")
	}

	proofLen := uint32(data[0])<<24 | uint32(data[1])<<16 | uint32(data[2])<<8 | uint32(data[3])
	if len(data) < int(4+proofLen) {
		return nil, fmt.Errorf("proof data truncated")
	}

	return &Proof{
		ProofData:    data[4 : 4+proofLen],
		PublicInputs: data[4+proofLen:],
	}, nil
}

// HashBTCQAddress hashes a BTCQ address string to get the binding commitment
func HashBTCQAddress(btcqAddress string) [32]byte {
	return sha256.Sum256([]byte(btcqAddress))
}

// SaveSetupToWriter writes the setup result to a writer
func SaveSetupToWriter(setup *SetupResult, w io.Writer) error {
	// Write constraint system
	_, err := setup.ConstraintSystem.WriteTo(w)
	if err != nil {
		return err
	}

	// Write proving key
	_, err = setup.ProvingKey.WriteTo(w)
	if err != nil {
		return err
	}

	// Write verifying key
	_, err = setup.VerifyingKey.WriteTo(w)
	if err != nil {
		return err
	}

	return nil
}

// LoadSetupFromReader reads a setup result from a reader
func LoadSetupFromReader(r io.Reader) (*SetupResult, error) {
	setup := &SetupResult{}

	// Read constraint system
	cs := groth16.NewCS(ecc.BN254)
	_, err := cs.ReadFrom(r)
	if err != nil {
		return nil, fmt.Errorf("failed to read constraint system: %w", err)
	}
	setup.ConstraintSystem = cs

	// Read proving key
	pk := groth16.NewProvingKey(ecc.BN254)
	_, err = pk.ReadFrom(r)
	if err != nil {
		return nil, fmt.Errorf("failed to read proving key: %w", err)
	}
	setup.ProvingKey = pk

	// Read verifying key
	vk := groth16.NewVerifyingKey(ecc.BN254)
	_, err = vk.ReadFrom(r)
	if err != nil {
		return nil, fmt.Errorf("failed to read verifying key: %w", err)
	}
	setup.VerifyingKey = vk

	return setup, nil
}
