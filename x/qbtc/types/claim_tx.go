package types

import (
	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/cosmos/cosmos-sdk/x/authz"
)

// A free claim transaction pays no fee, so it cannot be left to declare its own
// gas: a claim that runs out of gas in the message handler, which CheckTx does
// not run, would fail in its block, leave its UTXOs unclaimed, and could be
// sent again forever. It runs instead with a gas limit computed from the claim:
// FreeClaimBaseGas for the first UTXO and FreeClaimPerUTXOGas for each further
// one. Measured on the e2e network, a one-UTXO claim uses about 250,000 gas and
// each further UTXO about 35,500. The base also covers a transaction padded to
// FreeClaimMaxTxBytes, since the ante handler charges for every byte: every
// other field of the claim has a fixed or capped size.
const (
	FreeClaimBaseGas    uint64 = 450_000
	FreeClaimPerUTXOGas uint64 = 50_000
	FreeClaimMaxGas            = FreeClaimBaseGas + FreeClaimPerUTXOGas*(MaxBatchClaimUTXOs-1)
	FreeClaimMaxTxBytes        = 16 << 10
)

// FreeClaimGasLimit is the gas limit of a free claim of numUTXOs UTXOs.
func FreeClaimGasLimit(numUTXOs int) uint64 {
	n := uint64(min(max(numUTXOs, 1), MaxBatchClaimUTXOs))
	return FreeClaimBaseGas + FreeClaimPerUTXOGas*(n-1)
}

// FreeClaimTxGasLimit is the gas limit a free claim transaction runs with,
// whatever gas it declares. It is also the gas the transaction reports to
// CometBFT and counts against the block's max_gas. A transaction with more
// than one message, which the ante handler rejects, counts FreeClaimMaxGas.
func FreeClaimTxGasLimit(tx sdk.Tx) uint64 {
	msgs := tx.GetMsgs()
	if len(msgs) != 1 {
		return FreeClaimMaxGas
	}
	claim, ok := msgs[0].(*MsgClaimWithProof)
	if !ok {
		return FreeClaimMaxGas
	}
	return FreeClaimGasLimit(len(claim.Utxos))
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
