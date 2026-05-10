package types

import (
	"encoding/hex"
	"strconv"

	"github.com/cosmos/gogoproto/proto"
)

// GetKey returns a deterministic key for this BlockGossip — used by bifrost
// peers to deduplicate gossip and aggregate attestations against a single
// canonical commit.
func (m *BlockGossip) GetKey() string {
	bz, _ := proto.Marshal(m.GetCommit())
	return hex.EncodeToString(m.GetHash()) + "-" + strconv.FormatUint(m.GetHeight(), 10) + "-" + hex.EncodeToString(bz)
}
