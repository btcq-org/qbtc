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
