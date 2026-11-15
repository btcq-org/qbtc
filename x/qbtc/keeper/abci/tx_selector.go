package abci

import (
	"context"

	"github.com/cosmos/cosmos-sdk/baseapp"
	sdk "github.com/cosmos/cosmos-sdk/types"

	"github.com/btcq-org/qbtc/x/qbtc/types"
)

// txGas is the gas tx counts against max_gas: the gas it runs with. That is
// its declared gas limit, except for a free claim transaction, which runs with
// types.FreeClaimTxGasLimit whatever it declares.
func txGas(tx sdk.Tx) uint64 {
	if types.IsClaimOnlyTx(tx) {
		return types.FreeClaimTxGasLimit(tx)
	}
	if gasTx, ok := tx.(sdk.GasTx); ok {
		return gasTx.GetGas()
	}
	return 0
}

// NewTxSelector returns the SDK's default transaction selector, counting each
// transaction at txGas, the gas it runs with. Set it on the SDK's
// DefaultProposalHandler, which selects PrepareProposal's transactions. The
// SDK counts a transaction's declared gas, but a free claim runs
// with a limit computed from the claim, at most types.FreeClaimMaxGas, and
// CheckTx admits a claim declaring up to max_gas. Without this, a single such
// claim would use up the SDK's gas budget and leave every other transaction
// out of the block.
func NewTxSelector() baseapp.TxSelector {
	return txSelector{TxSelector: baseapp.NewDefaultTxSelector()}
}

type txSelector struct {
	baseapp.TxSelector
}

func (s txSelector) SelectTxForProposal(ctx context.Context, maxTxBytes, maxBlockGas uint64, memTx sdk.Tx, txBz []byte, _ uint64) bool {
	return s.TxSelector.SelectTxForProposal(ctx, maxTxBytes, maxBlockGas, memTx, txBz, txGas(memTx))
}
