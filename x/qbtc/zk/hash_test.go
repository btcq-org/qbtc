package zk

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ripemd160" //nolint:staticcheck // Bitcoin Hash160 is defined in terms of RIPEMD160.
)

// nativeHash160 computes RIPEMD160(SHA256(data)) using standard Go libraries.
// RIPEMD160 is no longer computed in-circuit — the verifier applies it natively
// to PubKeyHashSHA256 to recover the Bitcoin address hash.
func nativeHash160(data []byte) []byte {
	sha := sha256.Sum256(data)
	ripemd := ripemd160.New()
	ripemd.Write(sha[:])
	return ripemd.Sum(nil)
}

// computeRIPEMD160 computes RIPEMD160 using standard Go library.
func computeRIPEMD160(data []byte) []byte {
	hasher := ripemd160.New()
	hasher.Write(data)
	return hasher.Sum(nil)
}

func TestRIPEMD160Native_KnownVectors(t *testing.T) {
	testCases := []struct {
		name     string
		input    []byte
		expected string
	}{
		{"empty", []byte{}, "9c1185a5c5e9fc54612808977ee8f548b2258d31"},
		{"a", []byte("a"), "0bdc9d2d256b3ee9daae347be6f4dc835a467ffe"},
		{"abc", []byte("abc"), "8eb208f7e05d987a9b044a8e98c6b087f15a0bfc"},
		{"message digest", []byte("message digest"), "5d0689ef49d2fae572b881b123a85ffa21595f36"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, tc.expected, hex.EncodeToString(computeRIPEMD160(tc.input)))
		})
	}
}

func TestHash160Native(t *testing.T) {
	// Compressed pubkey for private key = 1.
	compressedPubKey, _ := hex.DecodeString("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")

	hash160 := nativeHash160(compressedPubKey)
	require.Len(t, hash160, 20)
	t.Logf("Hash160 of pubkey for privkey=1: %s", hex.EncodeToString(hash160))
}
