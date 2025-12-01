package zk

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestHashBTCQAddress(t *testing.T) {
	// Hash should be deterministic
	addr := "qbtc1abc123"
	hash1 := HashBTCQAddress(addr)
	hash2 := HashBTCQAddress(addr)
	require.Equal(t, hash1, hash2)

	// Different addresses should produce different hashes
	hash3 := HashBTCQAddress("qbtc1xyz789")
	require.NotEqual(t, hash1, hash3)

	// Hash should be 32 bytes (SHA256)
	require.Len(t, hash1, 32)
}
