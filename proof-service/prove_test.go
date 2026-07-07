package proofservice

import (
	"crypto/sha256"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
	btcecdsa "github.com/btcsuite/btcd/btcec/v2/ecdsa"
)

// fixed, non-secret test key
var testPrivKeyBytes = []byte{
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xab,
	0x54, 0xa9, 0x8c, 0xeb, 0x1f, 0x0a, 0xd2, 0x00,
	0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
}

// signFixture signs hash with the fixed test key and returns the pubkey and the
// 32-byte big-endian r and s components.
func signFixture(t *testing.T, hash []byte) (*btcec.PublicKey, []byte, []byte) {
	t.Helper()
	priv, pub := btcec.PrivKeyFromBytes(testPrivKeyBytes)
	sig := btcecdsa.Sign(priv, hash)
	r := sig.R()
	s := sig.S()
	rb := r.Bytes()
	sb := s.Bytes()
	return pub, rb[:], sb[:]
}

func TestVerifyECDSASignature_Valid(t *testing.T) {
	hash := sha256.Sum256([]byte("claim message"))
	pub, rb, sb := signFixture(t, hash[:])

	if err := verifyECDSASignature(pub, hash[:], rb, sb); err != nil {
		t.Fatalf("valid signature rejected: %v", err)
	}
}

func TestVerifyECDSASignature_WrongMessage(t *testing.T) {
	hash := sha256.Sum256([]byte("claim message"))
	pub, rb, sb := signFixture(t, hash[:])

	other := sha256.Sum256([]byte("different message"))
	if err := verifyECDSASignature(pub, other[:], rb, sb); err == nil {
		t.Fatal("expected verification to fail for a different message")
	}
}

func TestVerifyECDSASignature_WrongPubKey(t *testing.T) {
	hash := sha256.Sum256([]byte("claim message"))
	_, rb, sb := signFixture(t, hash[:])

	// A different key that did not produce the signature.
	otherBytes := make([]byte, 32)
	copy(otherBytes, testPrivKeyBytes)
	otherBytes[31] ^= 0x01
	_, otherPub := btcec.PrivKeyFromBytes(otherBytes)

	if err := verifyECDSASignature(otherPub, hash[:], rb, sb); err == nil {
		t.Fatal("expected verification to fail for the wrong public key")
	}
}

func TestVerifyECDSASignature_TamperedS(t *testing.T) {
	hash := sha256.Sum256([]byte("claim message"))
	pub, rb, sb := signFixture(t, hash[:])

	tampered := make([]byte, len(sb))
	copy(tampered, sb)
	tampered[31] ^= 0x01
	if err := verifyECDSASignature(pub, hash[:], rb, tampered); err == nil {
		t.Fatal("expected verification to fail for a tampered s value")
	}
}

func TestVerifyECDSASignature_ZeroComponents(t *testing.T) {
	hash := sha256.Sum256([]byte("claim message"))
	pub, rb, sb := signFixture(t, hash[:])
	zero := make([]byte, 32)

	if err := verifyECDSASignature(pub, hash[:], zero, sb); err == nil {
		t.Fatal("expected error for zero r")
	}
	if err := verifyECDSASignature(pub, hash[:], rb, zero); err == nil {
		t.Fatal("expected error for zero s")
	}
}
