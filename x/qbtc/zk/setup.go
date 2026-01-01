package zk

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254/kzg"
	"github.com/consensys/gnark/backend/plonk"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/scs"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/test/unsafekzg"
	ptau "github.com/mdehoog/gnark-ptau"
	"golang.org/x/crypto/blake2b"
)

const (
	// MaxProofDataLen is the maximum allowed proof data length (1MB).
	// PLONK proofs are typically ~1KB, so 1MB provides ample headroom.
	MaxProofDataLen = 1024 * 1024

	// MinProofDataLen is the minimum valid proof length.
	// A valid PLONK proof must be at least a few hundred bytes.
	MinProofDataLen = 100

	// HermezPtauURL is the URL template for downloading Hermez Powers of Tau files.
	// Use %d to specify the power (e.g., 16 for 2^16 constraints).
	HermezPtauURL = "https://storage.googleapis.com/zkevm/ptau/powersOfTau28_hez_final_%02d.ptau"

	// DefaultPtauPower is the default power for the PTAU file (2^21 = ~2M constraints).
	// This is more than enough for our circuit.
	DefaultPtauPower = 21
)

// Blake2b hashes for Hermez Powers of Tau ceremony outputs.
// From official snarkjs docs: https://github.com/iden3/snarkjs#7-prepare-phase-2
var ptauBlake2bHashes = map[int]string{
	21: "9aef0573cef4ded9c4a75f148709056bf989f80dad96876aadeb6f1c6d062391f07a394a9e756d16f7eb233198d5b69407cca44594c763ab4a5b67ae73254678",
}

// Secp256k1Fp is the base field of secp256k1
type Secp256k1Fp = emulated.Secp256k1Fp

// Secp256k1Fr is the scalar field of secp256k1
type Secp256k1Fr = emulated.Secp256k1Fr

// CircuitParams contains the curve and proof system parameters
type CircuitParams struct {
	Curve ecc.ID
}

// DefaultCircuitParams returns default parameters for the circuit
func DefaultCircuitParams() CircuitParams {
	return CircuitParams{
		Curve: ecc.BN254, // Use BN254 for PLONK
	}
}

// SetupResult contains the compiled circuit and keys from PLONK setup
type SetupResult struct {
	ConstraintSystem constraint.ConstraintSystem
	ProvingKey       plonk.ProvingKey
	VerifyingKey     plonk.VerifyingKey
}

// SetupMode specifies how the SRS should be obtained
type SetupMode int

const (
	// SetupModeTest uses an unsafe test SRS (development only)
	SetupModeTest SetupMode = iota
	// SetupModeFile loads SRS from a file
	SetupModeFile
	// SetupModeDownload downloads and caches the Hermez Powers of Tau
	SetupModeDownload
)

// SetupOptions configures the setup process
type SetupOptions struct {
	Mode SetupMode
	// SRSPath is the path to the SRS file (for SetupModeFile)
	SRSPath string
	// SRSLagrangePath is the path to the SRS Lagrange file (for SetupModeFile)
	SRSLagrangePath string
	// CacheDir is the directory to cache downloaded SRS files
	CacheDir string
	// PtauPower is the power for the PTAU file (default: DefaultPtauPower)
	PtauPower int
}

// DefaultSetupOptions returns default setup options for production.
// It will download and cache the Hermez Powers of Tau SRS.
func DefaultSetupOptions() SetupOptions {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		// Fallback to current directory with clear indication
		homeDir = "."
	}
	return SetupOptions{
		Mode:      SetupModeDownload,
		CacheDir:  filepath.Join(homeDir, ".qbtc", "zk-cache"),
		PtauPower: DefaultPtauPower,
	}
}

// TestSetupOptions returns setup options for testing.
// WARNING: Uses unsafe test SRS - DO NOT use in production!
func TestSetupOptions() SetupOptions {
	return SetupOptions{
		Mode: SetupModeTest,
	}
}

// SetupWithOptions performs PLONK setup for the BTCSignatureCircuit.
// This circuit is compatible with TSS/MPC signers.
// For production, use SetupModeDownload to use the Hermez/Polygon Powers of Tau.
func SetupWithOptions(opts SetupOptions) (*SetupResult, error) {
	// Create a placeholder circuit for compilation
	circuit := NewBTCSignatureCircuitPlaceholder()
	return SetupCircuitWithOptions(circuit, opts)
}

// SetupSchnorrWithOptions performs PLONK setup for the BTCSchnorrCircuit (Taproot).
func SetupSchnorrWithOptions(opts SetupOptions) (*SetupResult, error) {
	circuit := NewBTCSchnorrCircuitPlaceholder()
	return SetupCircuitWithOptions(circuit, opts)
}

// SetupP2SHP2WPKHWithOptions performs PLONK setup for the BTCP2SHP2WPKHCircuit.
func SetupP2SHP2WPKHWithOptions(opts SetupOptions) (*SetupResult, error) {
	circuit := NewBTCP2SHP2WPKHCircuitPlaceholder()
	return SetupCircuitWithOptions(circuit, opts)
}

// SetupP2PKWithOptions performs PLONK setup for the BTCP2PKCircuit.
func SetupP2PKWithOptions(opts SetupOptions) (*SetupResult, error) {
	circuit := NewBTCP2PKCircuitPlaceholder()
	return SetupCircuitWithOptions(circuit, opts)
}

// SetupP2WSHSingleKeyWithOptions performs PLONK setup for the BTCP2WSHSingleKeyCircuit.
func SetupP2WSHSingleKeyWithOptions(opts SetupOptions) (*SetupResult, error) {
	circuit := NewBTCP2WSHSingleKeyCircuitPlaceholder()
	return SetupCircuitWithOptions(circuit, opts)
}

// SetupCircuitWithOptions performs PLONK setup for any circuit.
func SetupCircuitWithOptions(circuit frontend.Circuit, opts SetupOptions) (*SetupResult, error) {
	// Compile the circuit to SCS (Sparse Constraint System for PLONK)
	cs, err := frontend.Compile(ecc.BN254.ScalarField(), scs.NewBuilder, circuit)
	if err != nil {
		return nil, fmt.Errorf("failed to compile circuit: %w", err)
	}

	fmt.Printf("Circuit compiled: %d constraints\n", cs.GetNbConstraints())

	var srs, srsLagrange *kzg.SRS

	switch opts.Mode {
	case SetupModeTest:
		// Generate a test SRS (for development only)
		// WARNING: This is NOT secure for production!
		srsCanon, srsLag, err := unsafekzg.NewSRS(cs)
		if err != nil {
			return nil, fmt.Errorf("failed to generate test SRS: %w", err)
		}
		srs = srsCanon.(*kzg.SRS)
		srsLagrange = srsLag.(*kzg.SRS)

	case SetupModeFile:
		// Load SRS from files
		srs, err = LoadBN254SRSFromFile(opts.SRSPath)
		if err != nil {
			return nil, fmt.Errorf("failed to load SRS from %s: %w", opts.SRSPath, err)
		}
		srsLagrange, err = LoadBN254SRSFromFile(opts.SRSLagrangePath)
		if err != nil {
			return nil, fmt.Errorf("failed to load SRS Lagrange from %s: %w", opts.SRSLagrangePath, err)
		}

	case SetupModeDownload:
		// Download and cache the Hermez Powers of Tau
		power := opts.PtauPower
		if power == 0 {
			power = DefaultPtauPower
		}
		srs, srsLagrange, err = LoadOrDownloadHermezSRS(opts.CacheDir, power, cs.GetNbConstraints())
		if err != nil {
			return nil, fmt.Errorf("failed to load/download Hermez SRS: %w", err)
		}

	default:
		return nil, fmt.Errorf("unknown setup mode: %d", opts.Mode)
	}

	// Run the PLONK setup
	pk, vk, err := plonk.Setup(cs, srs, srsLagrange)
	if err != nil {
		return nil, fmt.Errorf("failed to run PLONK setup: %w", err)
	}

	return &SetupResult{
		ConstraintSystem: cs,
		ProvingKey:       pk,
		VerifyingKey:     vk,
	}, nil
}

// LoadBN254SRSFromFile loads a BN254 KZG SRS from a gnark-formatted file
func LoadBN254SRSFromFile(path string) (*kzg.SRS, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("failed to open SRS file: %w", err)
	}
	defer f.Close()

	var srs kzg.SRS
	_, err = srs.ReadFrom(f)
	if err != nil {
		return nil, fmt.Errorf("failed to read SRS: %w", err)
	}

	return &srs, nil
}

func DownloadFile(url, localFilePathName string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to download PTAU: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("failed to download PTAU: HTTP %d", resp.StatusCode)
	}
	f, err := os.Create(localFilePathName)
	if err != nil {
		return fmt.Errorf("failed to create local file: %w", err)
	}
	defer f.Close()
	_, err = io.Copy(f, resp.Body)
	if err != nil {
		return fmt.Errorf("failed to save PTAU to local file: %w", err)
	}
	return nil
}

// LoadOrDownloadHermezSRS loads the Hermez Powers of Tau SRS from cache,
// or downloads it if not cached. The SRS is converted to gnark format.
func LoadOrDownloadHermezSRS(cacheDir string, power int, minConstraints int) (*kzg.SRS, *kzg.SRS, error) {
	// Ensure cache directory exists
	if err := os.MkdirAll(cacheDir, 0755); err != nil {
		return nil, nil, fmt.Errorf("failed to create cache dir: %w", err)
	}

	// Check constraint count
	maxConstraints := 1 << power
	if minConstraints > maxConstraints {
		return nil, nil, fmt.Errorf("circuit has %d constraints but SRS only supports %d (2^%d); increase power",
			minConstraints, maxConstraints, power)
	}

	// Paths for cached files
	srsPath := filepath.Join(cacheDir, fmt.Sprintf("srs_bn254_%d.dat", power))
	srsLagrangePath := filepath.Join(cacheDir, fmt.Sprintf("srs_lagrange_bn254_%d_%d.dat", power, minConstraints))
	rawSRSLagrangePath := filepath.Join(cacheDir, fmt.Sprintf("raw_srs_lagrange_bn254_%d_%d.dat", power, minConstraints))
	// Check if cached files exist
	if fileExists(srsPath) && fileExists(srsLagrangePath) {
		fmt.Printf("Loading cached SRS from %s\n", cacheDir)
		srs, err := LoadBN254SRSFromFile(srsPath)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to load cached SRS: %w", err)
		}
		srsLagrange, err := LoadBN254SRSFromFile(srsLagrangePath)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to load cached SRS Lagrange: %w", err)
		}
		return srs, srsLagrange, nil
	}

	if !fileExists(rawSRSLagrangePath) {
		ptauURL := fmt.Sprintf(HermezPtauURL, power)
		// Download and convert the PTAU file
		fmt.Printf("Downloading Hermez Powers of Tau (2^%d), from %s...\n", power, ptauURL)
		if err := DownloadFile(ptauURL, rawSRSLagrangePath); err != nil {
			return nil, nil, fmt.Errorf("failed to download PTAU file: %w", err)
		}

		// Verify Blake2b hash (security check against tampering)
		// Hashes from: https://github.com/iden3/snarkjs#7-prepare-phase-2
		if expectedHash, ok := ptauBlake2bHashes[power]; ok {
			if err := verifyFileBlake2b(rawSRSLagrangePath, expectedHash); err != nil {
				os.Remove(rawSRSLagrangePath) // Remove corrupted/tampered file
				return nil, nil, fmt.Errorf("PTAU hash verification failed: %w", err)
			}
			fmt.Printf("PTAU Blake2b hash verified for power %d\n", power)
		}
	}
	file, err := os.Open(rawSRSLagrangePath)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to open downloaded PTAU file: %w", err)
	}
	defer file.Close()
	srs, err := ptau.ToSRS(file)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to convert PTAU to gnark SRS: %w", err)
	}
	// Generate Lagrange form for PLONK
	// We need the next power of 2 that fits the constraint count
	lagrangeSize := nextPowerOfTwo(minConstraints)
	fmt.Printf("Generating Lagrange SRS for size %d...\n", lagrangeSize)

	srsLagrange, err := kzg.ToLagrangeG1(srs.Pk.G1[:lagrangeSize])
	if err != nil {
		return nil, nil, fmt.Errorf("failed to compute Lagrange SRS: %w", err)
	}

	// Build the Lagrange SRS structure
	srsLagrangeResult := &kzg.SRS{
		Pk: kzg.ProvingKey{
			G1: srsLagrange,
		},
		Vk: srs.Vk,
	}

	// Cache the converted SRS
	fmt.Printf("Caching SRS to %s\n", cacheDir)
	if err := saveBN254SRSToFile(srs, srsPath); err != nil {
		fmt.Printf("Warning: failed to cache SRS: %v\n", err)
	}
	if err := saveBN254SRSToFile(srsLagrangeResult, srsLagrangePath); err != nil {
		fmt.Printf("Warning: failed to cache SRS Lagrange: %v\n", err)
	}

	return srs, srsLagrangeResult, nil
}

// nextPowerOfTwo returns the smallest power of 2 >= n
func nextPowerOfTwo(n int) int {
	p := 1
	for p < n {
		p *= 2
	}
	return p
}

func fileExists(path string) bool {
	f, err := os.Stat(path)
	return err == nil && !f.IsDir()
}

// verifyFileBlake2b verifies the Blake2b-512 hash of a file against an expected hash.
// Uses streaming to avoid loading large PTAU files (hundreds of MB) into memory.
func verifyFileBlake2b(filePath, expectedHash string) error {
	file, err := os.Open(filePath)
	if err != nil {
		return fmt.Errorf("failed to open file: %w", err)
	}
	defer file.Close()

	hash, err := blake2b.New512(nil)
	if err != nil {
		return fmt.Errorf("failed to create blake2b hasher: %w", err)
	}
	if _, err := io.Copy(hash, file); err != nil {
		return fmt.Errorf("failed to hash file: %w", err)
	}
	actualHash := fmt.Sprintf("%x", hash.Sum(nil))

	if actualHash != expectedHash {
		return fmt.Errorf("hash mismatch: expected %s, got %s", expectedHash, actualHash)
	}
	return nil
}

func saveBN254SRSToFile(srs *kzg.SRS, path string) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	_, err = srs.WriteTo(f)
	return err
}

// SerializeVerifyingKey serializes the verifying key to bytes
func SerializeVerifyingKey(vk plonk.VerifyingKey) ([]byte, error) {
	var buf bytes.Buffer
	_, err := vk.WriteTo(&buf)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize verifying key: %w", err)
	}
	return buf.Bytes(), nil
}

// DeserializeVerifyingKey deserializes a verifying key from bytes
func DeserializeVerifyingKey(data []byte) (plonk.VerifyingKey, error) {
	vk := plonk.NewVerifyingKey(ecc.BN254)
	_, err := vk.ReadFrom(bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("failed to deserialize verifying key: %w", err)
	}
	return vk, nil
}

// SerializeProvingKey serializes the proving key to bytes
func SerializeProvingKey(pk plonk.ProvingKey) ([]byte, error) {
	var buf bytes.Buffer
	_, err := pk.WriteTo(&buf)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize proving key: %w", err)
	}
	return buf.Bytes(), nil
}

// DeserializeProvingKey deserializes a proving key from bytes
func DeserializeProvingKey(data []byte) (plonk.ProvingKey, error) {
	pk := plonk.NewProvingKey(ecc.BN254)
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
	cs := plonk.NewCS(ecc.BN254)
	_, err := cs.ReadFrom(bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("failed to deserialize constraint system: %w", err)
	}
	return cs, nil
}

// Prover handles proof generation for signature-based claims using PLONK.
// This prover is TSS/MPC compatible - it generates proofs of ECDSA signature validity.
type Prover struct {
	cs constraint.ConstraintSystem
	pk plonk.ProvingKey
}

// NewProver creates a new prover with the given constraint system and proving key
func NewProver(cs constraint.ConstraintSystem, pk plonk.ProvingKey) *Prover {
	return &Prover{cs: cs, pk: pk}
}

// ProverFromSetup creates a prover from setup result
func ProverFromSetup(setup *SetupResult) *Prover {
	return NewProver(setup.ConstraintSystem, setup.ProvingKey)
}

// ProofParams contains all parameters needed to generate a signature-based proof
type ProofParams struct {
	// Signature components (both are scalars in ECDSA)
	SignatureR *big.Int // r scalar (x-coordinate of k·G reduced mod n)
	SignatureS *big.Int // s scalar

	// Public key (uncompressed coordinates)
	PublicKeyX *big.Int
	PublicKeyY *big.Int

	// Public inputs
	MessageHash     [32]byte // The signed message hash
	AddressHash     [20]byte // Hash160 of the public key
	BTCQAddressHash [32]byte // H(claimer_address)
	ChainID         [8]byte  // First 8 bytes of H(chain_id)
}

// GenerateProof generates a PLONK proof that proves ownership of a Bitcoin address
// using an ECDSA signature. The signature and public key are private inputs.
func (p *Prover) GenerateProof(params ProofParams) (*Proof, error) {
	// Create witness assignment
	assignment := &BTCSignatureCircuit{}

	// Set signature R scalar (the 'r' value in ECDSA, x-coord of k·G mod n)
	assignment.SignatureR.Limbs = bigIntToLimbs(params.SignatureR)

	// Set signature S scalar
	assignment.SignatureS.Limbs = bigIntToLimbs(params.SignatureS)

	// Set public key X
	assignment.PublicKeyX.Limbs = bigIntToLimbs(params.PublicKeyX)

	// Set public key Y
	assignment.PublicKeyY.Limbs = bigIntToLimbs(params.PublicKeyY)

	// Set the message hash (public input)
	for i := 0; i < 32; i++ {
		assignment.MessageHash[i] = params.MessageHash[i]
	}

	// Set the address hash (public input)
	for i := 0; i < 20; i++ {
		assignment.AddressHash[i] = params.AddressHash[i]
	}

	// Set the BTCQ address hash (public input)
	for i := 0; i < 32; i++ {
		assignment.BTCQAddressHash[i] = params.BTCQAddressHash[i]
	}

	// Set the chain ID (public input)
	for i := 0; i < 8; i++ {
		assignment.ChainID[i] = params.ChainID[i]
	}

	// Create the full witness
	witness, err := frontend.NewWitness(assignment, ecc.BN254.ScalarField())
	if err != nil {
		return nil, fmt.Errorf("failed to create witness: %w", err)
	}

	// Generate the PLONK proof
	proof, err := plonk.Prove(p.cs, p.pk, witness)
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

// bigIntToLimbs converts a big.Int to 4 limbs of 64 bits each for emulated field elements
func bigIntToLimbs(n *big.Int) []frontend.Variable {
	limbs := make([]frontend.Variable, 4)

	if n == nil {
		for i := range 4 {
			limbs[i] = big.NewInt(0)
		}
		return limbs
	}

	// Pad to 32 bytes
	nBytes := n.Bytes()
	padded := make([]byte, 32)
	copy(padded[32-len(nBytes):], nBytes)

	// Convert to limbs (little-endian limb order, big-endian within limb)
	for i := range 4 {
		limb := new(big.Int)
		limbBytes := padded[24-i*8 : 32-i*8]
		limb.SetBytes(limbBytes)
		limbs[i] = limb
	}

	return limbs
}

// HashBTCQAddress hashes a BTCQ address string to get the binding commitment
func HashBTCQAddress(btcqAddress string) [32]byte {
	return sha256.Sum256([]byte(btcqAddress))
}

// SchnorrProver handles proof generation for Taproot claims using Schnorr signatures.
type SchnorrProver struct {
	cs constraint.ConstraintSystem
	pk plonk.ProvingKey
}

// NewSchnorrProver creates a new Schnorr prover
func NewSchnorrProver(cs constraint.ConstraintSystem, pk plonk.ProvingKey) *SchnorrProver {
	return &SchnorrProver{cs: cs, pk: pk}
}

// SchnorrProverFromSetup creates a Schnorr prover from setup result
func SchnorrProverFromSetup(setup *SetupResult) *SchnorrProver {
	return NewSchnorrProver(setup.ConstraintSystem, setup.ProvingKey)
}

// GenerateProof generates a PLONK proof for a Taproot Schnorr signature claim
func (p *SchnorrProver) GenerateProof(params SchnorrProofParams) (*Proof, error) {
	assignment := &BTCSchnorrCircuit{}

	assignment.SignatureR.Limbs = bigIntToLimbs(params.SignatureR)
	assignment.SignatureS.Limbs = bigIntToLimbs(params.SignatureS)
	assignment.PublicKeyX.Limbs = bigIntToLimbs(params.PublicKeyX)
	assignment.PublicKeyY.Limbs = bigIntToLimbs(params.PublicKeyY)

	for i := 0; i < 32; i++ {
		assignment.MessageHash[i] = params.MessageHash[i]
		assignment.XOnlyPubKey[i] = params.XOnlyPubKey[i]
		assignment.BTCQAddressHash[i] = params.BTCQAddressHash[i]
	}
	for i := 0; i < 8; i++ {
		assignment.ChainID[i] = params.ChainID[i]
	}

	witness, err := frontend.NewWitness(assignment, ecc.BN254.ScalarField())
	if err != nil {
		return nil, fmt.Errorf("failed to create witness: %w", err)
	}

	proof, err := plonk.Prove(p.cs, p.pk, witness)
	if err != nil {
		return nil, fmt.Errorf("failed to generate proof: %w", err)
	}

	var proofBuf bytes.Buffer
	_, err = proof.WriteTo(&proofBuf)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize proof: %w", err)
	}

	publicWitness, err := witness.Public()
	if err != nil {
		return nil, fmt.Errorf("failed to get public witness: %w", err)
	}

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

// P2SHP2WPKHProver handles proof generation for P2SH-wrapped P2WPKH claims.
type P2SHP2WPKHProver struct {
	cs constraint.ConstraintSystem
	pk plonk.ProvingKey
}

// NewP2SHP2WPKHProver creates a new P2SH-P2WPKH prover
func NewP2SHP2WPKHProver(cs constraint.ConstraintSystem, pk plonk.ProvingKey) *P2SHP2WPKHProver {
	return &P2SHP2WPKHProver{cs: cs, pk: pk}
}

// P2SHP2WPKHProverFromSetup creates a P2SH-P2WPKH prover from setup result
func P2SHP2WPKHProverFromSetup(setup *SetupResult) *P2SHP2WPKHProver {
	return NewP2SHP2WPKHProver(setup.ConstraintSystem, setup.ProvingKey)
}

// GenerateProof generates a PLONK proof for a P2SH-P2WPKH claim
func (p *P2SHP2WPKHProver) GenerateProof(params P2SHP2WPKHProofParams) (*Proof, error) {
	assignment := &BTCP2SHP2WPKHCircuit{}

	assignment.SignatureR.Limbs = bigIntToLimbs(params.SignatureR)
	assignment.SignatureS.Limbs = bigIntToLimbs(params.SignatureS)
	assignment.PublicKeyX.Limbs = bigIntToLimbs(params.PublicKeyX)
	assignment.PublicKeyY.Limbs = bigIntToLimbs(params.PublicKeyY)

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

	witness, err := frontend.NewWitness(assignment, ecc.BN254.ScalarField())
	if err != nil {
		return nil, fmt.Errorf("failed to create witness: %w", err)
	}

	proof, err := plonk.Prove(p.cs, p.pk, witness)
	if err != nil {
		return nil, fmt.Errorf("failed to generate proof: %w", err)
	}

	var proofBuf bytes.Buffer
	_, err = proof.WriteTo(&proofBuf)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize proof: %w", err)
	}

	publicWitness, err := witness.Public()
	if err != nil {
		return nil, fmt.Errorf("failed to get public witness: %w", err)
	}

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

// P2PKProver handles proof generation for P2PK claims.
type P2PKProver struct {
	cs constraint.ConstraintSystem
	pk plonk.ProvingKey
}

// NewP2PKProver creates a new P2PK prover
func NewP2PKProver(cs constraint.ConstraintSystem, pk plonk.ProvingKey) *P2PKProver {
	return &P2PKProver{cs: cs, pk: pk}
}

// P2PKProverFromSetup creates a P2PK prover from setup result
func P2PKProverFromSetup(setup *SetupResult) *P2PKProver {
	return NewP2PKProver(setup.ConstraintSystem, setup.ProvingKey)
}

// GenerateProof generates a PLONK proof for a P2PK claim
func (p *P2PKProver) GenerateProof(params P2PKProofParams) (*Proof, error) {
	assignment := &BTCP2PKCircuit{}

	assignment.SignatureR.Limbs = bigIntToLimbs(params.SignatureR)
	assignment.SignatureS.Limbs = bigIntToLimbs(params.SignatureS)
	assignment.PublicKeyX.Limbs = bigIntToLimbs(params.PublicKeyX)
	assignment.PublicKeyY.Limbs = bigIntToLimbs(params.PublicKeyY)

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

	witness, err := frontend.NewWitness(assignment, ecc.BN254.ScalarField())
	if err != nil {
		return nil, fmt.Errorf("failed to create witness: %w", err)
	}

	proof, err := plonk.Prove(p.cs, p.pk, witness)
	if err != nil {
		return nil, fmt.Errorf("failed to generate proof: %w", err)
	}

	var proofBuf bytes.Buffer
	_, err = proof.WriteTo(&proofBuf)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize proof: %w", err)
	}

	publicWitness, err := witness.Public()
	if err != nil {
		return nil, fmt.Errorf("failed to get public witness: %w", err)
	}

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

// P2WSHSingleKeyProver handles proof generation for P2WSH single-key claims.
type P2WSHSingleKeyProver struct {
	cs constraint.ConstraintSystem
	pk plonk.ProvingKey
}

// NewP2WSHSingleKeyProver creates a new P2WSH single-key prover
func NewP2WSHSingleKeyProver(cs constraint.ConstraintSystem, pk plonk.ProvingKey) *P2WSHSingleKeyProver {
	return &P2WSHSingleKeyProver{cs: cs, pk: pk}
}

// P2WSHSingleKeyProverFromSetup creates a P2WSH single-key prover from setup result
func P2WSHSingleKeyProverFromSetup(setup *SetupResult) *P2WSHSingleKeyProver {
	return NewP2WSHSingleKeyProver(setup.ConstraintSystem, setup.ProvingKey)
}

// GenerateProof generates a PLONK proof for a P2WSH single-key claim
func (p *P2WSHSingleKeyProver) GenerateProof(params P2WSHSingleKeyProofParams) (*Proof, error) {
	assignment := &BTCP2WSHSingleKeyCircuit{}

	assignment.SignatureR.Limbs = bigIntToLimbs(params.SignatureR)
	assignment.SignatureS.Limbs = bigIntToLimbs(params.SignatureS)
	assignment.PublicKeyX.Limbs = bigIntToLimbs(params.PublicKeyX)
	assignment.PublicKeyY.Limbs = bigIntToLimbs(params.PublicKeyY)

	for i := 0; i < 32; i++ {
		assignment.MessageHash[i] = params.MessageHash[i]
		assignment.WitnessProgram[i] = params.WitnessProgram[i]
		assignment.BTCQAddressHash[i] = params.BTCQAddressHash[i]
	}
	for i := 0; i < 8; i++ {
		assignment.ChainID[i] = params.ChainID[i]
	}

	witness, err := frontend.NewWitness(assignment, ecc.BN254.ScalarField())
	if err != nil {
		return nil, fmt.Errorf("failed to create witness: %w", err)
	}

	proof, err := plonk.Prove(p.cs, p.pk, witness)
	if err != nil {
		return nil, fmt.Errorf("failed to generate proof: %w", err)
	}

	var proofBuf bytes.Buffer
	_, err = proof.WriteTo(&proofBuf)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize proof: %w", err)
	}

	publicWitness, err := witness.Public()
	if err != nil {
		return nil, fmt.Errorf("failed to get public witness: %w", err)
	}

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

// VerificationParams contains parameters needed for proof verification
type VerificationParams struct {
	MessageHash     [32]byte // The message that was signed
	AddressHash     [20]byte // Hash160 of BTC pubkey
	BTCQAddressHash [32]byte // H(claimer_address) - note: named BTCQ to match test conventions
	ChainID         [8]byte  // First 8 bytes of H(chain_id)
}

// Proof represents a serialized PLONK proof with its public inputs
type Proof struct {
	ProofData    []byte // Serialized PLONK proof
	PublicInputs []byte // Serialized public inputs
}

// ToProtoZKProof serializes the proof to a format suitable for protobuf transmission
func (p *Proof) ToProtoZKProof() []byte {
	// Format: [4-byte proof length][proof data][public inputs]
	result := make([]byte, 4+len(p.ProofData)+len(p.PublicInputs))
	// Length as big-endian
	result[0] = byte(len(p.ProofData) >> 24)
	result[1] = byte(len(p.ProofData) >> 16)
	result[2] = byte(len(p.ProofData) >> 8)
	result[3] = byte(len(p.ProofData))
	copy(result[4:], p.ProofData)
	copy(result[4+len(p.ProofData):], p.PublicInputs)
	return result
}

// ProofFromProtoZKProof deserializes a proof from protobuf format
// Returns defensive copies to prevent memory aliasing issues
func ProofFromProtoZKProof(data []byte) (*Proof, error) {
	if len(data) < 4 {
		return nil, fmt.Errorf("proof data too short")
	}
	proofLen := int(data[0])<<24 | int(data[1])<<16 | int(data[2])<<8 | int(data[3])
	if proofLen < MinProofDataLen || proofLen > MaxProofDataLen {
		return nil, fmt.Errorf("invalid proof length: %d", proofLen)
	}
	if len(data) < 4+proofLen {
		return nil, fmt.Errorf("proof data truncated")
	}

	// Defensive copy to prevent memory aliasing
	proofData := make([]byte, proofLen)
	copy(proofData, data[4:4+proofLen])

	publicInputs := make([]byte, len(data)-(4+proofLen))
	copy(publicInputs, data[4+proofLen:])

	return &Proof{
		ProofData:    proofData,
		PublicInputs: publicInputs,
	}, nil
}

// ComputeChainIDHash computes the chain ID hash from a chain ID string.
// Returns the first 8 bytes of SHA256(chain_id).
func ComputeChainIDHash(chainID string) [8]byte {
	hash := sha256.Sum256([]byte(chainID))
	var result [8]byte
	copy(result[:], hash[:8])
	return result
}

// SaveSetupToWriter writes the setup result to a writer
func SaveSetupToWriter(setup *SetupResult, w io.Writer) error {
	// Write constraint system
	_, err := setup.ConstraintSystem.WriteTo(w)
	if err != nil {
		return fmt.Errorf("failed to write constraint system: %w", err)
	}

	// Write proving key
	_, err = setup.ProvingKey.WriteTo(w)
	if err != nil {
		return fmt.Errorf("failed to write proving key: %w", err)
	}

	// Write verifying key
	_, err = setup.VerifyingKey.WriteTo(w)
	if err != nil {
		return fmt.Errorf("failed to write verifying key: %w", err)
	}

	return nil
}

// LoadSetupFromReader reads a setup result from a reader
func LoadSetupFromReader(r io.Reader) (*SetupResult, error) {
	setup := &SetupResult{}

	// Read constraint system
	cs := plonk.NewCS(ecc.BN254)
	_, err := cs.ReadFrom(r)
	if err != nil {
		return nil, fmt.Errorf("failed to read constraint system: %w", err)
	}
	setup.ConstraintSystem = cs

	// Read proving key
	pk := plonk.NewProvingKey(ecc.BN254)
	_, err = pk.ReadFrom(r)
	if err != nil {
		return nil, fmt.Errorf("failed to read proving key: %w", err)
	}
	setup.ProvingKey = pk

	// Read verifying key
	vk := plonk.NewVerifyingKey(ecc.BN254)
	_, err = vk.ReadFrom(r)
	if err != nil {
		return nil, fmt.Errorf("failed to read verifying key: %w", err)
	}
	setup.VerifyingKey = vk

	return setup, nil
}
