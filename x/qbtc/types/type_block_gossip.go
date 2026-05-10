package types

import (
	"crypto/sha256"
	"encoding/hex"
	"strconv"

	"github.com/cosmos/gogoproto/proto"
)

// GetKey returns a deterministic key for this BlockGossip — used by bifrost
// peers to deduplicate gossip and aggregate attestations against a single
// canonical commit. The commit fingerprint is sha256(proto.Marshal(commit)) so
// the key stays bounded; hex-encoding the full commit (a few thousand txs in
// the typical case) would inflate the LevelDB key by megabytes per block.
func (m *BlockGossip) GetKey() string {
	bz, _ := proto.Marshal(m.GetCommit())
	digest := sha256.Sum256(bz)
	return hex.EncodeToString(m.GetHash()) + "-" + strconv.FormatUint(m.GetHeight(), 10) + "-" + hex.EncodeToString(digest[:])
}
