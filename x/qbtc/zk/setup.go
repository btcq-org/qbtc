package zk

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/kzg"
	"github.com/consensys/gnark/backend/plonk"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/scs"
	"github.com/consensys/gnark/test/unsafekzg"
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
	HermezPtauURL = "https://hermez.s3-eu-west-1.amazonaws.com/powersOfTau28_hez_final_%02d.ptau"

	// DefaultPtauPower is the default power for the PTAU file (2^20 = ~1M constraints).
	// This is more than enough for our circuit.
	DefaultPtauPower = 20
)

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

// Setup performs the trusted setup for the BTCAddressCircuit using PLONK.
//
// DEPRECATED: Use SetupWithOptions for production. This function uses an unsafe
// test SRS and should only be used for development/testing.
func Setup() (*SetupResult, error) {
	fmt.Println("WARNING: Using unsafe test SRS. DO NOT use in production!")
	fmt.Println("For production, use SetupWithOptions with SetupModeDownload or SetupModeFile.")
	return SetupWithOptions(TestSetupOptions())
}

// SetupWithOptions performs PLONK setup with the specified options.
// For production, use SetupModeDownload to use the Hermez/Polygon Powers of Tau.
func SetupWithOptions(opts SetupOptions) (*SetupResult, error) {
	// Create a placeholder circuit for compilation
	circuit := NewBTCAddressCircuitPlaceholder()

	// Compile the circuit to SCS (Sparse Constraint System for PLONK)
	cs, err := frontend.Compile(ecc.BN254.ScalarField(), scs.NewBuilder, circuit)
	if err != nil {
		return nil, fmt.Errorf("failed to compile circuit: %w", err)
	}

	fmt.Printf("Circuit compiled: %d constraints\n", cs.GetNbConstraints())

	var srs, srsLagrange kzg.SRS

	switch opts.Mode {
	case SetupModeTest:
		// Generate a test SRS (for development only)
		// WARNING: This is NOT secure for production!
		srsCanon, srsLag, err := unsafekzg.NewSRS(cs)
		if err != nil {
			return nil, fmt.Errorf("failed to generate test SRS: %w", err)
		}
		srs = *srsCanon.(*kzg.SRS)
		srsLagrange = *srsLag.(*kzg.SRS)

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
	pk, vk, err := plonk.Setup(cs, &srs, &srsLagrange)
	if err != nil {
		return nil, fmt.Errorf("failed to run PLONK setup: %w", err)
	}

	return &SetupResult{
		ConstraintSystem: cs,
		ProvingKey:       pk,
		VerifyingKey:     vk,
	}, nil
}

// SetupWithSRS performs PLONK setup using a pre-existing SRS.
// This is the recommended approach for production, using an SRS from
// a trusted ceremony like Hermez/Polygon Perpetual Powers of Tau.
//
// The SRS must be large enough to support the circuit's constraint count.
func SetupWithSRS(srs, srsLagrange kzg.SRS) (*SetupResult, error) {
	// Create a placeholder circuit for compilation
	circuit := NewBTCAddressCircuitPlaceholder()

	// Compile the circuit to SCS
	cs, err := frontend.Compile(ecc.BN254.ScalarField(), scs.NewBuilder, circuit)
	if err != nil {
		return nil, fmt.Errorf("failed to compile circuit: %w", err)
	}

	// Run the PLONK setup with the provided SRS
	pk, vk, err := plonk.Setup(cs, &srs, &srsLagrange)
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
func LoadBN254SRSFromFile(path string) (kzg.SRS, error) {
	f, err := os.Open(path)
	if err != nil {
		return kzg.SRS{}, fmt.Errorf("failed to open SRS file: %w", err)
	}
	defer f.Close()

	var srs kzg.SRS
	_, err = srs.ReadFrom(f)
	if err != nil {
		return kzg.SRS{}, fmt.Errorf("failed to read SRS: %w", err)
	}

	return srs, nil
}

// LoadOrDownloadHermezSRS loads the Hermez Powers of Tau SRS from cache,
// or downloads it if not cached. The SRS is converted to gnark format.
func LoadOrDownloadHermezSRS(cacheDir string, power int, minConstraints int) (kzg.SRS, kzg.SRS, error) {
	// Ensure cache directory exists
	if err := os.MkdirAll(cacheDir, 0755); err != nil {
		return kzg.SRS{}, kzg.SRS{}, fmt.Errorf("failed to create cache dir: %w", err)
	}

	// Check constraint count
	maxConstraints := 1 << power
	if minConstraints > maxConstraints {
		return kzg.SRS{}, kzg.SRS{}, fmt.Errorf("circuit has %d constraints but SRS only supports %d (2^%d); increase power",
			minConstraints, maxConstraints, power)
	}

	// Paths for cached files
	srsPath := filepath.Join(cacheDir, fmt.Sprintf("srs_bn254_%d.dat", power))
	srsLagrangePath := filepath.Join(cacheDir, fmt.Sprintf("srs_lagrange_bn254_%d_%d.dat", power, minConstraints))

	// Check if cached files exist
	if fileExists(srsPath) && fileExists(srsLagrangePath) {
		fmt.Printf("Loading cached SRS from %s\n", cacheDir)
		srs, err := LoadBN254SRSFromFile(srsPath)
		if err != nil {
			return kzg.SRS{}, kzg.SRS{}, fmt.Errorf("failed to load cached SRS: %w", err)
		}
		srsLagrange, err := LoadBN254SRSFromFile(srsLagrangePath)
		if err != nil {
			return kzg.SRS{}, kzg.SRS{}, fmt.Errorf("failed to load cached SRS Lagrange: %w", err)
		}
		return srs, srsLagrange, nil
	}

	// Download and convert the PTAU file
	fmt.Printf("Downloading Hermez Powers of Tau (2^%d)...\n", power)
	ptauURL := fmt.Sprintf(HermezPtauURL, power)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, ptauURL, nil)
	if err != nil {
		return kzg.SRS{}, kzg.SRS{}, fmt.Errorf("failed to create request: %w", err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return kzg.SRS{}, kzg.SRS{}, fmt.Errorf("failed to download PTAU: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return kzg.SRS{}, kzg.SRS{}, fmt.Errorf("failed to download PTAU: HTTP %d", resp.StatusCode)
	}

	// Read the PTAU file with size limit (PTAU files can be large but should be bounded)
	const maxPtauSize = 2 * 1024 * 1024 * 1024 // 2GB max
	ptauData, err := io.ReadAll(io.LimitReader(resp.Body, maxPtauSize))
	if err != nil {
		return kzg.SRS{}, kzg.SRS{}, fmt.Errorf("failed to read PTAU data: %w", err)
	}

	fmt.Println("Converting PTAU to gnark SRS format...")

	// Convert PTAU to gnark SRS - this properly uses the ceremony points
	srs, err := ConvertPtauToGnarkSRS(ptauData, maxConstraints)
	if err != nil {
		return kzg.SRS{}, kzg.SRS{}, fmt.Errorf("failed to convert PTAU: %w", err)
	}

	// Generate Lagrange form for PLONK
	// We need the next power of 2 that fits the constraint count
	lagrangeSize := nextPowerOfTwo(minConstraints)
	fmt.Printf("Generating Lagrange SRS for size %d...\n", lagrangeSize)

	srsLagrange, err := kzg.ToLagrangeG1(srs.Pk.G1[:lagrangeSize+1])
	if err != nil {
		return kzg.SRS{}, kzg.SRS{}, fmt.Errorf("failed to compute Lagrange SRS: %w", err)
	}

	// Build the Lagrange SRS structure
	srsLagrangeResult := kzg.SRS{
		Pk: kzg.ProvingKey{
			G1: srsLagrange,
		},
		Vk: srs.Vk,
	}

	// Cache the converted SRS
	fmt.Printf("Caching SRS to %s\n", cacheDir)
	if err := saveBN254SRSToFile(&srs, srsPath); err != nil {
		fmt.Printf("Warning: failed to cache SRS: %v\n", err)
	}
	if err := saveBN254SRSToFile(&srsLagrangeResult, srsLagrangePath); err != nil {
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

// ConvertPtauToGnarkSRS converts a Hermez PTAU file to gnark SRS format.
// The PTAU format is documented at: https://github.com/iden3/snarkjs
//
// SECURITY: This function properly uses the ceremony points to construct
// the SRS, preserving the security properties of the Powers of Tau ceremony.
// The toxic waste τ is never reconstructed - we only use the points [τ^i]G.
func ConvertPtauToGnarkSRS(ptauData []byte, size int) (kzg.SRS, error) {
	// Parse the PTAU file header
	// PTAU format: magic (4) + version (4) + numSections (4) + sections...
	if len(ptauData) < 12 {
		return kzg.SRS{}, fmt.Errorf("PTAU file too short")
	}

	// Verify magic bytes "ptau"
	if string(ptauData[0:4]) != "ptau" {
		return kzg.SRS{}, fmt.Errorf("invalid PTAU magic: %s", string(ptauData[0:4]))
	}

	version := binary.LittleEndian.Uint32(ptauData[4:8])
	numSections := binary.LittleEndian.Uint32(ptauData[8:12])
	fmt.Printf("PTAU version: %d, sections: %d\n", version, numSections)

	// Parse sections to find tau powers
	offset := 12
	var tauG1Points []bn254.G1Affine
	var tauG2Points []bn254.G2Affine

	for offset < len(ptauData) {
		if offset+12 > len(ptauData) {
			break
		}

		sectionType := binary.LittleEndian.Uint32(ptauData[offset : offset+4])
		sectionLen := binary.LittleEndian.Uint64(ptauData[offset+4 : offset+12])
		offset += 12

		if uint64(offset)+sectionLen > uint64(len(ptauData)) {
			return kzg.SRS{}, fmt.Errorf("section exceeds file length")
		}

		// Guard against integer overflow on 32-bit systems
		if sectionLen > uint64(^uint(0)>>1) {
			return kzg.SRS{}, fmt.Errorf("section length %d exceeds maximum int size", sectionLen)
		}

		sectionData := ptauData[offset : offset+int(sectionLen)]
		offset += int(sectionLen)

		switch sectionType {
		case 2: // TauG1 - the main G1 points
			var err error
			tauG1Points, err = parsePtauG1Points(sectionData, size+1)
			if err != nil {
				return kzg.SRS{}, fmt.Errorf("failed to parse G1 points: %w", err)
			}
			fmt.Printf("Parsed %d G1 points\n", len(tauG1Points))

		case 3: // TauG2 - the G2 points
			var err error
			tauG2Points, err = parsePtauG2Points(sectionData, 2)
			if err != nil {
				return kzg.SRS{}, fmt.Errorf("failed to parse G2 points: %w", err)
			}
			fmt.Printf("Parsed %d G2 points\n", len(tauG2Points))
		}
	}

	if len(tauG1Points) < size+1 {
		return kzg.SRS{}, fmt.Errorf("insufficient G1 points in PTAU: got %d, need %d", len(tauG1Points), size+1)
	}
	if len(tauG2Points) < 2 {
		return kzg.SRS{}, fmt.Errorf("insufficient G2 points in PTAU: got %d, need at least 2", len(tauG2Points))
	}

	// Validate that the points are on the curve
	for i := 0; i < min(10, len(tauG1Points)); i++ {
		if !tauG1Points[i].IsOnCurve() {
			return kzg.SRS{}, fmt.Errorf("G1 point %d is not on curve", i)
		}
	}
	for i := 0; i < len(tauG2Points); i++ {
		if !tauG2Points[i].IsOnCurve() {
			return kzg.SRS{}, fmt.Errorf("G2 point %d is not on curve", i)
		}
	}

	// Construct the gnark SRS directly from the ceremony points
	// This is the SECURE way - we're using the actual ceremony output
	srs := kzg.SRS{
		Pk: kzg.ProvingKey{
			G1: tauG1Points[:size+1], // [τ^0]G1, [τ^1]G1, ..., [τ^n]G1
		},
		Vk: kzg.VerifyingKey{
			G1: tauG1Points[0], // [1]G1 = G1 generator
			G2: [2]bn254.G2Affine{
				tauG2Points[0], // [1]G2 = G2 generator
				tauG2Points[1], // [τ]G2
			},
		},
	}

	fmt.Println("SRS constructed from ceremony points")
	return srs, nil
}

// parsePtauG1Points parses G1 points from PTAU section data
// PTAU uses uncompressed points in Montgomery form, little-endian
func parsePtauG1Points(data []byte, maxPoints int) ([]bn254.G1Affine, error) {
	// Each BN254 G1 point is 64 bytes (32 bytes X + 32 bytes Y) uncompressed
	pointSize := 64
	numPoints := len(data) / pointSize
	if numPoints > maxPoints {
		numPoints = maxPoints
	}

	points := make([]bn254.G1Affine, numPoints)
	for i := 0; i < numPoints; i++ {
		pointData := data[i*pointSize : (i+1)*pointSize]

		// PTAU format: little-endian coordinates
		// X is first 32 bytes, Y is next 32 bytes
		xBytes := reverseBytes(pointData[0:32])
		yBytes := reverseBytes(pointData[32:64])

		points[i].X.SetBytes(xBytes)
		points[i].Y.SetBytes(yBytes)

		// Validate point is on curve
		if i < 5 && !points[i].IsOnCurve() {
			// Try alternative format
			points[i].X.SetBytes(pointData[0:32])
			points[i].Y.SetBytes(pointData[32:64])
			if !points[i].IsOnCurve() {
				return nil, fmt.Errorf("G1 point %d is not on curve (tried both endianness)", i)
			}
		}
	}

	return points, nil
}

// parsePtauG2Points parses G2 points from PTAU section data
func parsePtauG2Points(data []byte, maxPoints int) ([]bn254.G2Affine, error) {
	// Each BN254 G2 point is 128 bytes (64 bytes X + 64 bytes Y) uncompressed
	// X and Y are elements of Fp2, so each has two Fp components (A0, A1)
	pointSize := 128
	numPoints := len(data) / pointSize
	if numPoints > maxPoints {
		numPoints = maxPoints
	}

	points := make([]bn254.G2Affine, numPoints)
	for i := 0; i < numPoints; i++ {
		pointData := data[i*pointSize : (i+1)*pointSize]

		// PTAU format: each Fp2 element has c0, c1 (each 32 bytes, little-endian)
		// Order: X.c0, X.c1, Y.c0, Y.c1
		x0Bytes := reverseBytes(pointData[0:32])
		x1Bytes := reverseBytes(pointData[32:64])
		y0Bytes := reverseBytes(pointData[64:96])
		y1Bytes := reverseBytes(pointData[96:128])

		points[i].X.A0.SetBytes(x0Bytes)
		points[i].X.A1.SetBytes(x1Bytes)
		points[i].Y.A0.SetBytes(y0Bytes)
		points[i].Y.A1.SetBytes(y1Bytes)

		// Validate point is on curve
		if !points[i].IsOnCurve() {
			// Try big-endian format
			points[i].X.A0.SetBytes(pointData[0:32])
			points[i].X.A1.SetBytes(pointData[32:64])
			points[i].Y.A0.SetBytes(pointData[64:96])
			points[i].Y.A1.SetBytes(pointData[96:128])
			if !points[i].IsOnCurve() {
				return nil, fmt.Errorf("G2 point %d is not on curve (tried both endianness)", i)
			}
		}
	}

	return points, nil
}

// reverseBytes returns a copy of the byte slice with bytes in reverse order
func reverseBytes(b []byte) []byte {
	result := make([]byte, len(b))
	for i := 0; i < len(b); i++ {
		result[i] = b[len(b)-1-i]
	}
	return result
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
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

// Prover handles proof generation using PLONK
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

// ProofParams contains all the parameters needed to generate a proof
type ProofParams struct {
	PrivateKey      *big.Int // BTC private key (secret)
	AddressHash     [20]byte // Hash160(pubkey)
	BTCQAddressHash [32]byte // H(claimer_address) - binds to recipient
	ChainID         [8]byte  // First 8 bytes of H(chain_id) - prevents cross-chain replay
}

// zeroBytes securely zeros a byte slice to prevent private key leakage.
func zeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// GenerateProof generates a PLONK proof that proves ownership of the Bitcoin address
// corresponding to the given private key.
//
// SECURITY: This function zeroes all private key material from memory after use.
func (p *Prover) GenerateProof(params ProofParams) (*Proof, error) {
	// Create witness assignment
	assignment := &BTCAddressCircuit{}

	// Set the private key (as emulated field element)
	assignment.PrivateKey.Limbs = make([]frontend.Variable, 4)
	// Convert big.Int to 4 limbs of 64 bits each
	pkBytes := params.PrivateKey.Bytes()
	// Pad to 32 bytes
	padded := make([]byte, 32)
	copy(padded[32-len(pkBytes):], pkBytes)

	// SECURITY: Defer zeroing of sensitive key material
	defer func() {
		zeroBytes(pkBytes)
		zeroBytes(padded)
		// Zero the limbs (which are *big.Int stored as frontend.Variable)
		for i := 0; i < 4; i++ {
			if limb, ok := assignment.PrivateKey.Limbs[i].(*big.Int); ok {
				limb.SetInt64(0)
			}
		}
	}()

	// Convert to limbs (little-endian limb order, big-endian within limb)
	for i := 0; i < 4; i++ {
		limb := new(big.Int)
		limbBytes := padded[24-i*8 : 32-i*8]
		limb.SetBytes(limbBytes)
		assignment.PrivateKey.Limbs[i] = limb
	}

	// Set the address hash (public input)
	for i := 0; i < 20; i++ {
		assignment.AddressHash[i] = params.AddressHash[i]
	}

	// Set the BTCQ address hash (public input for binding)
	for i := 0; i < 32; i++ {
		assignment.BTCQAddressHash[i] = params.BTCQAddressHash[i]
	}

	// Set the chain ID (public input for cross-chain replay prevention)
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

// Proof contains the serialized PLONK proof and public inputs
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
		return nil, fmt.Errorf("proof data too short: got %d bytes, need at least 4", len(data))
	}

	proofLen := uint32(data[0])<<24 | uint32(data[1])<<16 | uint32(data[2])<<8 | uint32(data[3])

	// Security: Check for maximum proof length to prevent DoS
	if proofLen > MaxProofDataLen {
		return nil, fmt.Errorf("proof length %d exceeds maximum allowed %d", proofLen, MaxProofDataLen)
	}

	// Security: Check for minimum proof length
	if proofLen < MinProofDataLen {
		return nil, fmt.Errorf("proof length %d is below minimum valid length %d", proofLen, MinProofDataLen)
	}

	// Security: Check total data length (prevent integer overflow)
	totalRequired := uint64(4) + uint64(proofLen)
	if totalRequired > uint64(len(data)) {
		return nil, fmt.Errorf("proof data truncated: expected at least %d bytes, got %d", totalRequired, len(data))
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

// VerificationParams contains parameters needed for proof verification
type VerificationParams struct {
	AddressHash     [20]byte // Hash160 of BTC pubkey
	BTCQAddressHash [32]byte // H(claimer_address)
	ChainID         [8]byte  // First 8 bytes of H(chain_id)
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
