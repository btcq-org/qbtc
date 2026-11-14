package types

import (
	sdk "github.com/cosmos/cosmos-sdk/types"
)

// IsClaimOnlyTx reports whether every message of tx is a MsgClaimWithProof.
// Such a transaction pays no fee.
func IsClaimOnlyTx(tx sdk.Tx) bool {
	msgs := tx.GetMsgs()
	if len(msgs) == 0 {
		return false
	}
	for _, msg := range msgs {
		if _, ok := msg.(*MsgClaimWithProof); !ok {
			return false
		}
	}
	return true
}
