package types

import (
	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/cosmos/cosmos-sdk/x/authz"
)

// A free claim transaction runs with the gas it declares, clamped to
// [FreeClaimMinGas, FreeClaimMaxGas]. Measured on the e2e network: a one-UTXO
// claim uses about 250,000 gas and each further UTXO about 35,500, so the
// floor covers the usual claim of a few UTXOs and the ceiling a full batch of
// MaxBatchClaimUTXOs.
const (
	FreeClaimMinGas uint64 = 400_000
	FreeClaimMaxGas uint64 = 3_000_000
)

// FreeClaimGasLimit is the gas limit of a free claim transaction that declares
// the given gas. It is also the gas the transaction reports to CometBFT and
// counts against the block's max_gas. It must be finite: once max_gas is set,
// CometBFT drops a transaction whose reported gas is negative, as an infinite
// gas meter's is.
func FreeClaimGasLimit(declared uint64) uint64 {
	return min(max(declared, FreeClaimMinGas), FreeClaimMaxGas)
}

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

// CountClaimMsgs returns the number of MsgClaimWithProof messages in msgs,
// including those nested in authz MsgExec. Each one costs a PLONK
// verification when the block runs.
func CountClaimMsgs(msgs []sdk.Msg) int {
	n := 0
	for _, msg := range msgs {
		switch m := msg.(type) {
		case *MsgClaimWithProof:
			n++
		case *authz.MsgExec:
			inner, err := m.GetMessages()
			if err != nil {
				continue
			}
			n += CountClaimMsgs(inner)
		}
	}
	return n
}
