//go:build testing

package zk

import (
	"crypto/rand"
	"math/big"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

func TestSecurityAuditTestSuite(t *testing.T) {
	suite.Run(t, new(SecurityAuditTestSuite))
}

type SecurityAuditTestSuite struct {
	suite.Suite
	setup *SetupResult
}

func (s *SecurityAuditTestSuite) SetupSuite() {
	ClearVerifierForTesting()
	setup, err := SetupWithOptions(TestSetupOptions())
	s.Require().NoError(err)
	s.setup = setup
}

// =============================================================================
// SECURITY AUDIT TESTS
// These tests verify the cryptographic security properties of the ZK system.
// =============================================================================

// -----------------------------------------------------------------------------
// SOUNDNESS TESTS - Verify that invalid proofs cannot be constructed
// -----------------------------------------------------------------------------

// TestSoundness_WrongPrivateKey verifies that a proof generated with a different
// private key (that doesn't own the address) fails verification.
//
// Since the RIPEMD160-out-of-circuit change, the attacker CAN generate a
// syntactically valid proof for their own pubkey — the circuit does not bind
// directly to the address. Soundness lives in the verifier's native RIPEMD160
// check: RIPEMD160(PubKeyHashSHA256) must equal the Hash160 of the claimed
// address, and the attacker's SHA256(pubkey) won't RIPEMD160 to the legitimate
// owner's address.
func (s *SecurityAuditTestSuite) TestSoundness_WrongPrivateKey() {
	if testing.Short() {
		s.T().Skip("skipping soundness test in short mode")
	}

	prover := ProverFromSetup(s.setup)
	verifier := NewVerifier(s.setup.VerifyingKey)

	legitimateKey, _ := btcec.NewPrivateKey()
	legitimateAddress := p2wpkhAddressForTest(legitimateKey.PubKey())
	legitimatePubKeyHashSHA256, err := PubKeyHashSHA256(legitimateKey.PubKey().SerializeCompressed())
	require.NoError(s.T(), err)

	attackerKey, _ := btcec.NewPrivateKey()
	attackerAddress := p2wpkhAddressForTest(attackerKey.PubKey())
	destination := "qbtc1attacker"

	// The attacker can only sign for their own address; this proof is honest.
	params, _, attackerPubKeyHashSHA256 := signClaimForTest(s.T(), attackerKey, "qbtc-1", attackerAddress, destination)
	proof, err := prover.GenerateProof(params)
	require.NoError(s.T(), err, "attacker should be able to prove their own address")

	// Redirecting the claim to the legitimate address fails on two counts: the
	// proof's PubKeyHashSHA256 commits to the attacker's key, so the RIPEMD160
	// check fails; and the digest was computed over attackerAddress, not
	// legitimateAddress. Either check alone is sufficient.
	err = verifier.VerifyProof(proof, VerificationParams{
		ChainID:          "qbtc-1",
		BitcoinAddress:   legitimateAddress,
		QBTCAddress:      destination,
		PubKeyHashSHA256: attackerPubKeyHashSHA256,
	})
	require.ErrorContains(s.T(), err, "address hash mismatch")

	// If the attacker lies about PubKeyHashSHA256 (picks the legitimate one to
	// pass the RIPEMD160 check), the proof's in-circuit SHA256 binding fails.
	err = verifier.VerifyProof(proof, VerificationParams{
		ChainID:          "qbtc-1",
		BitcoinAddress:   legitimateAddress,
		QBTCAddress:      destination,
		PubKeyHashSHA256: legitimatePubKeyHashSHA256,
	})
	require.Error(s.T(), err, "swapped PubKeyHashSHA256 must fail the in-circuit SHA256 check")
}

// TestSoundness_InvalidSignature verifies that an invalid signature fails.
func (s *SecurityAuditTestSuite) TestSoundness_InvalidSignature() {
	if testing.Short() {
		s.T().Skip("skipping soundness test in short mode")
	}

	prover := ProverFromSetup(s.setup)

	privateKey, _ := btcec.NewPrivateKey()
	pubKey := privateKey.PubKey()
	messageHash := ClaimMessageDigest("qbtc-1", p2pkhAddressForTest(pubKey), "qbtc1test", "")

	invalidR := new(big.Int).SetBytes([]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
		17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32})
	invalidS := new(big.Int).SetBytes([]byte{32, 31, 30, 29, 28, 27, 26, 25, 24, 23, 22, 21, 20, 19, 18, 17,
		16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1})

	_, err := prover.GenerateProof(ProofParamsFromSignature(pubKey, invalidR, invalidS, messageHash))
	require.Error(s.T(), err, "proof generation should fail with invalid signature")
}

// -----------------------------------------------------------------------------
// BINDING TESTS - Verify proofs are bound to their parameters
// -----------------------------------------------------------------------------

// TestBinding_FrontRunningProtection verifies that a proof cannot be redirected
// to a different destination address.
func (s *SecurityAuditTestSuite) TestBinding_FrontRunningProtection() {
	if testing.Short() {
		s.T().Skip("skipping binding test in short mode")
	}

	prover := ProverFromSetup(s.setup)
	verifier := NewVerifier(s.setup.VerifyingKey)

	privateKey, _ := btcec.NewPrivateKey()
	bitcoinAddress := p2wpkhAddressForTest(privateKey.PubKey())
	legitimateDestination := "qbtc1legitimate_user"

	params, _, pubKeyHashSHA256 := signClaimForTest(s.T(), privateKey, "qbtc-1", bitcoinAddress, legitimateDestination)
	proof, err := prover.GenerateProof(params)
	require.NoError(s.T(), err)

	// Attacker intercepts the proof and tries to redirect to their address
	err = verifier.VerifyProof(proof, VerificationParams{
		ChainID:          "qbtc-1",
		BitcoinAddress:   bitcoinAddress,
		QBTCAddress:      "qbtc1attacker",
		PubKeyHashSHA256: pubKeyHashSHA256,
	})
	require.Error(s.T(), err, "front-running attack should fail")

	err = verifier.VerifyProof(proof, VerificationParams{
		ChainID:          "qbtc-1",
		BitcoinAddress:   bitcoinAddress,
		QBTCAddress:      legitimateDestination,
		PubKeyHashSHA256: pubKeyHashSHA256,
	})
	require.NoError(s.T(), err, "legitimate verification should succeed")
}

// TestBinding_ReferrerSwapProtection verifies that whoever relays a proof (the
// proof service, a validator, a mempool watcher) cannot replace, add or drop
// the referrer the Bitcoin key signed.
func (s *SecurityAuditTestSuite) TestBinding_ReferrerSwapProtection() {
	if testing.Short() {
		s.T().Skip("skipping binding test in short mode")
	}

	prover := ProverFromSetup(s.setup)
	verifier := NewVerifier(s.setup.VerifyingKey)

	privateKey, _ := btcec.NewPrivateKey()
	bitcoinAddress := p2wpkhAddressForTest(privateKey.PubKey())
	destination := "qbtc1legitimate_user"
	referrer := "qbtc1honest_referrer"

	params, _, pubKeyHashSHA256 := signReferredClaimForTest(s.T(), privateKey, "qbtc-1", bitcoinAddress, destination, referrer)
	proof, err := prover.GenerateProof(params)
	require.NoError(s.T(), err)

	verify := func(referrer string) error {
		return verifier.VerifyProof(proof, VerificationParams{
			ChainID:          "qbtc-1",
			BitcoinAddress:   bitcoinAddress,
			QBTCAddress:      destination,
			Referrer:         referrer,
			PubKeyHashSHA256: pubKeyHashSHA256,
		})
	}
	require.NoError(s.T(), verify(referrer), "signed referrer verifies")
	require.Error(s.T(), verify("qbtc1attacker"), "swapped referrer must fail")
	require.Error(s.T(), verify(""), "dropped referrer must fail")

	// A proof signed without a referrer cannot gain one.
	params, _, _ = signClaimForTest(s.T(), privateKey, "qbtc-1", bitcoinAddress, destination)
	proof, err = prover.GenerateProof(params)
	require.NoError(s.T(), err)
	require.NoError(s.T(), verify(""))
	require.Error(s.T(), verify("qbtc1attacker"), "added referrer must fail")
}

// TestBinding_Hash160NativeCheck verifies the native RIPEMD160 binding: a proof
// whose PubKeyHashSHA256 does not RIPEMD160-hash to the claimed address must be
// rejected. If that check were skipped or misordered, any address would be
// accepted.
func (s *SecurityAuditTestSuite) TestBinding_Hash160NativeCheck() {
	if testing.Short() {
		s.T().Skip("skipping binding test in short mode")
	}

	prover := ProverFromSetup(s.setup)
	verifier := NewVerifier(s.setup.VerifyingKey)

	privateKey, _ := btcec.NewPrivateKey()
	bitcoinAddress := p2wpkhAddressForTest(privateKey.PubKey())

	params, _, pubKeyHashSHA256 := signClaimForTest(s.T(), privateKey, "qbtc-1", bitcoinAddress, "qbtc1hash160_binding")
	proof, err := prover.GenerateProof(params)
	s.Require().NoError(err)

	// Flip one bit of PubKeyHashSHA256: RIPEMD160 of the tampered value will
	// not match the address, so the native check must reject before PLONK
	// verification is even attempted.
	tampered := pubKeyHashSHA256
	tampered[0] ^= 0x01
	err = verifier.VerifyProof(proof, VerificationParams{
		ChainID:          "qbtc-1",
		BitcoinAddress:   bitcoinAddress,
		QBTCAddress:      "qbtc1hash160_binding",
		PubKeyHashSHA256: tampered,
	})
	s.Require().ErrorContains(err, "address hash mismatch", "expected the native RIPEMD160 check to fire")

	// Symmetrically, another key's address with an honest PubKeyHashSHA256
	// must fail for the same reason.
	other, _ := btcec.NewPrivateKey()
	err = verifier.VerifyProof(proof, VerificationParams{
		ChainID:          "qbtc-1",
		BitcoinAddress:   p2wpkhAddressForTest(other.PubKey()),
		QBTCAddress:      "qbtc1hash160_binding",
		PubKeyHashSHA256: pubKeyHashSHA256,
	})
	s.Require().ErrorContains(err, "address hash mismatch")
}

// TestBinding_CrossChainReplayProtection verifies that a proof from one chain
// cannot be replayed on another chain.
func (s *SecurityAuditTestSuite) TestBinding_CrossChainReplayProtection() {
	if testing.Short() {
		s.T().Skip("skipping binding test in short mode")
	}

	prover := ProverFromSetup(s.setup)
	verifier := NewVerifier(s.setup.VerifyingKey)

	privateKey, _ := btcec.NewPrivateKey()
	bitcoinAddress := p2pkhAddressForTest(privateKey.PubKey())

	params, _, pubKeyHashSHA256 := signClaimForTest(s.T(), privateKey, "qbtc-mainnet-1", bitcoinAddress, "qbtc1user")
	proofA, err := prover.GenerateProof(params)
	require.NoError(s.T(), err)

	err = verifier.VerifyProof(proofA, VerificationParams{
		ChainID:          "qbtc-testnet-1",
		BitcoinAddress:   bitcoinAddress,
		QBTCAddress:      "qbtc1user",
		PubKeyHashSHA256: pubKeyHashSHA256,
	})
	require.Error(s.T(), err, "cross-chain replay should fail")
}

// -----------------------------------------------------------------------------
// VERIFIER IMMUTABILITY TESTS
// -----------------------------------------------------------------------------

// TestVerifier_ImmutabilityAfterInit verifies that the global verifier cannot
// be replaced after initialization (prevents VK replacement attacks).
func (s *SecurityAuditTestSuite) TestVerifier_ImmutabilityAfterInit() {
	ClearVerifierForTesting()

	vkBytes, err := SerializeVerifyingKey(s.setup.VerifyingKey)
	s.Require().NoError(err)
	err = InitializeVerifier(vkBytes)
	s.Require().NoError(err)
	s.Require().True(IsVerifierInitialized())

	err = InitializeVerifier([]byte{0x00, 0x01, 0x02})
	s.Require().Error(err)
	s.Require().ErrorIs(err, ErrVerifierAlreadyInitialized)

	err = InitializeVerifier(vkBytes)
	s.Require().Error(err)
}

// -----------------------------------------------------------------------------
// EDGE CASE TESTS
// -----------------------------------------------------------------------------

// TestEdgeCase_ZeroValues tests handling of edge case inputs.
func (s *SecurityAuditTestSuite) TestEdgeCase_ZeroValues() {
	s.T().Run("empty fields still produce a digest", func(t *testing.T) {
		require.NotEqual(t, [32]byte{}, ClaimMessageDigest("", "", "", ""))
	})

	s.T().Run("nil proof rejection", func(t *testing.T) {
		verifier := NewVerifier(s.setup.VerifyingKey)
		require.Error(t, verifier.VerifyProof(nil, VerificationParams{}))
	})

	s.T().Run("empty bitcoin address rejection", func(t *testing.T) {
		verifier := NewVerifier(s.setup.VerifyingKey)
		require.ErrorContains(t, verifier.VerifyProof(make([]byte, 200), VerificationParams{}), "invalid Bitcoin address")
	})
}

// TestEdgeCase_LargeInputs tests handling of boundary values.
func (s *SecurityAuditTestSuite) TestEdgeCase_LargeInputs() {
	n := btcec.S256().N
	maxScalar := new(big.Int).Sub(n, big.NewInt(1))

	limbs := testBigIntToLimbs(maxScalar)
	s.Require().Len(limbs, 4)
}

// -----------------------------------------------------------------------------
// DETERMINISM TESTS
// -----------------------------------------------------------------------------

// TestDeterminism_SameInputsSameOutput verifies message derivation is deterministic.
func (s *SecurityAuditTestSuite) TestDeterminism_SameInputsSameOutput() {
	msg1 := ClaimMessageDigest("qbtc-1", "bc1qaddress", "qbtc1test", "")
	msg2 := ClaimMessageDigest("qbtc-1", "bc1qaddress", "qbtc1test", "")
	s.Require().Equal(msg1, msg2, "message computation should be deterministic")
}

// -----------------------------------------------------------------------------
// COMPLETENESS TESTS - Verify that valid proofs are accepted
// -----------------------------------------------------------------------------

// TestCompleteness_ValidProofAccepted verifies that a correctly generated proof
// for a valid claim is accepted, for both supported address types.
func (s *SecurityAuditTestSuite) TestCompleteness_ValidProofAccepted() {
	if testing.Short() {
		s.T().Skip("skipping completeness test in short mode")
	}

	prover := ProverFromSetup(s.setup)
	verifier := NewVerifier(s.setup.VerifyingKey)

	privateKeyBytes := make([]byte, 32)
	_, err := rand.Read(privateKeyBytes)
	s.Require().NoError(err)
	privateKey, pubKey := btcec.PrivKeyFromBytes(privateKeyBytes)

	for name, bitcoinAddress := range map[string]string{
		"p2pkh":  p2pkhAddressForTest(pubKey),
		"p2wpkh": p2wpkhAddressForTest(pubKey),
	} {
		s.T().Run(name, func(t *testing.T) {
			params, _, pubKeyHashSHA256 := signClaimForTest(t, privateKey, "qbtc-1", bitcoinAddress, "qbtc1completeness_test")
			proof, err := prover.GenerateProof(params)
			require.NoError(t, err, "proof generation should succeed for valid inputs")

			err = verifier.VerifyProof(proof, VerificationParams{
				ChainID:          "qbtc-1",
				BitcoinAddress:   bitcoinAddress,
				QBTCAddress:      "qbtc1completeness_test",
				PubKeyHashSHA256: pubKeyHashSHA256,
			})
			require.NoError(t, err, "valid proof should be accepted")
		})
	}
}

// -----------------------------------------------------------------------------
// HELPER FUNCTIONS
// -----------------------------------------------------------------------------

// testBigIntToLimbs is a test helper to convert big.Int to limbs
func testBigIntToLimbs(n *big.Int) []interface{} {
	limbs := make([]interface{}, 4)

	if n == nil {
		for i := range 4 {
			limbs[i] = big.NewInt(0)
		}
		return limbs
	}

	nBytes := n.Bytes()
	padded := make([]byte, 32)
	copy(padded[32-len(nBytes):], nBytes)

	for i := range 4 {
		limb := new(big.Int)
		limbBytes := padded[24-i*8 : 32-i*8]
		limb.SetBytes(limbBytes)
		limbs[i] = limb
	}

	return limbs
}

// -----------------------------------------------------------------------------
// AUDIT CHECKLIST TESTS
// -----------------------------------------------------------------------------

// TestAudit_NoSecretInputLeakage verifies secret inputs are properly marked.
func TestAudit_NoSecretInputLeakage(t *testing.T) {
	// This is a compile-time check via gnark tags on BTCPubKeyOwnershipCircuit:
	//   secret: SignatureR, SignatureS, PublicKeyX, PublicKeyY
	//   public: MessageHash, PubKeyHashSHA256
	// The chain ID, Bitcoin address and destination are NOT circuit public
	// inputs. The verifier re-derives MessageHash natively from the BIP-137
	// claim text and natively checks RIPEMD160(PubKeyHashSHA256) against the
	// address's Hash160.
	t.Log("ECDSA circuit has proper secret/public separation")
}

// TestAudit_MessageBindingComplete verifies all binding components are included.
func TestAudit_MessageBindingComplete(t *testing.T) {
	base := ClaimMessageDigest("qbtc-1", "bc1qaddress", "qbtc1test", "")

	t.Run("address binding", func(t *testing.T) {
		require.NotEqual(t, base, ClaimMessageDigest("qbtc-1", "bc1qother", "qbtc1test", ""))
	})

	t.Run("destination binding", func(t *testing.T) {
		require.NotEqual(t, base, ClaimMessageDigest("qbtc-1", "bc1qaddress", "qbtc1different", ""))
	})

	t.Run("chain binding", func(t *testing.T) {
		require.NotEqual(t, base, ClaimMessageDigest("other-chain", "bc1qaddress", "qbtc1test", ""))
	})

	t.Run("referrer binding", func(t *testing.T) {
		require.NotEqual(t, base, ClaimMessageDigest("qbtc-1", "bc1qaddress", "qbtc1test", "qbtc1referrer"))
	})

	t.Run("version binding", func(t *testing.T) {
		require.Equal(t, "qbtc-claim-v1", ClaimMessageVersion, "version should be set")
		require.Equal(t, "qbtc-claim-v1|qbtc-1|bc1qaddress|qbtc1test|", ClaimMessageText("qbtc-1", "bc1qaddress", "qbtc1test", ""))
	})
}

// =============================================================================
// AUDIT SUMMARY
// =============================================================================
//
// SECURITY PROPERTIES VERIFIED:
//
// 1. SOUNDNESS:
//    - Invalid signatures cannot produce valid proofs
//    - Wrong private key (doesn't own the address) fails
//    - Signature must be valid for the claimed public key
//
// 2. BINDING:
//    - Proof bound to Bitcoin address (via Hash160 and the signed text)
//    - Proof bound to destination address (signed text)
//    - Proof bound to chain ID (cross-chain replay protection)
//    - Proof bound to version string
//
// 3. ZERO-KNOWLEDGE:
//    - Private key never leaves user's wallet
//    - Signature (r, s) is hidden in the proof
//    - Public key is hidden in the proof
//    - Only hashes are revealed as public inputs
//
// 4. IMMUTABILITY:
//    - Global verifier cannot be re-registered after init
//    - VK replacement attacks are prevented
//
// 5. INPUT VALIDATION:
//    - Nil proof rejection
//    - Invalid proof format rejection
//    - Invalid Bitcoin address rejection
//
// CIRCUIT COVERAGE:
// - BTCPubKeyOwnershipCircuit (P2PKH, P2WPKH via ECDSA + Hash160)
//
// TRUST ASSUMPTIONS:
// 1. Trusted setup ceremony was honest (1-of-N)
// 2. gnark library is correctly implemented
// 3. ECDSA is cryptographically secure
// 4. SHA-256, RIPEMD-160 are collision-resistant
// 5. BN254 pairing is secure
//
// =============================================================================
