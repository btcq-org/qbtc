package ebifrost

import (
	storetypes "cosmossdk.io/store/types"
	"github.com/btcq-org/qbtc/x/qbtc/types"
	sdk "github.com/cosmos/cosmos-sdk/types"
)

type FreeClaimDecorator struct{}

func NewFreeClaimDecorator() FreeClaimDecorator {
	return FreeClaimDecorator{}
}

// AnteHandle makes MsgClaimWithProof transactions free by setting an infinite
// gas meter and zero minimum gas prices. This must be placed after
// SetUpContextDecorator so the gas meter override takes effect for all
// downstream decorators (fee deduction, sig gas, etc.).
func (fcd FreeClaimDecorator) AnteHandle(ctx sdk.Context, tx sdk.Tx, simulate bool, next sdk.AnteHandler) (sdk.Context, error) {
	if isClaimOnlyTx(tx) {
		ctx = ctx.
			WithGasMeter(storetypes.NewInfiniteGasMeter()).
			WithMinGasPrices(sdk.DecCoins{})
	}

	return next(ctx, tx, simulate)
}

// isClaimOnlyTx returns true if the tx contains only MsgClaimWithProof messages.
func isClaimOnlyTx(tx sdk.Tx) bool {
	msgs := tx.GetMsgs()
	if len(msgs) == 0 {
		return false
	}
	for _, msg := range msgs {
		if _, ok := msg.(*types.MsgClaimWithProof); !ok {
			return false
		}
	}
	return true
}
