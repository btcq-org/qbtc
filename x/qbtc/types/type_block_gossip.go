package types

import (
	"crypto/sha256"
	"encoding/hex"
	"strconv"
)

// GetKey returns the unique key for the BlockGossip message, which is its hash.
func (m *BlockGossip) GetKey() string {
	contentHash := sha256.Sum256(m.BlockContent)
	return m.GetHash() + "-" + strconv.FormatUint(m.GetHeight(), 10) + "-" + hex.EncodeToString(contentHash[:])
}

// BlockAttestationKey identifies the attestations for one block content: the
// block hash, height and the hash of the uncompressed commit that attestations
// sign. Gossip for the same block shares the key even when validators'
// compressed bytes differ.
func BlockAttestationKey(hash string, height uint64, signBytes []byte) string {
	commitHash := sha256.Sum256(signBytes)
	return hash + "-" + strconv.FormatUint(height, 10) + "-" + hex.EncodeToString(commitHash[:])
}
