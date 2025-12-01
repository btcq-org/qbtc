package ebifrost

import (
	"github.com/btcq-org/qbtc/x/qbtc/types"
	sdk "github.com/cosmos/cosmos-sdk/types"
)

type EnshrinedBifrostPostDecorator struct {
	EnshrinedBifrost *EnshrinedBifrost
}

func NewEnshrineBifrostPostDecorator(eb *EnshrinedBifrost) *EnshrinedBifrostPostDecorator {
	return &EnshrinedBifrostPostDecorator{
		EnshrinedBifrost: eb,
	}
}

func (e *EnshrinedBifrostPostDecorator) PostHandle(ctx sdk.Context, tx sdk.Tx, simulate, success bool, next sdk.PostHandler) (newCtx sdk.Context, err error) {
	if simulate || !success {
		return next(ctx, tx, simulate, success)
	}

	if _, ok := tx.(wInjectTx); !ok {
		return next(ctx, tx, simulate, success)
	}

	// if the tx is a wInjectTx, then we need to inform enshrined bifrost that the tx has been processed.
	for _, msg := range tx.GetMsgs() {
		switch m := msg.(type) {
		case *types.MsgBtcBlock:
			e.EnshrinedBifrost.MarkBlockAsProcessed(ctx, m)
		}
	}

	return next(ctx, tx, simulate, success)
}
