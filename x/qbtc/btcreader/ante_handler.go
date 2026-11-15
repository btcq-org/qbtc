package btcreader

import (
	"fmt"

	"github.com/btcq-org/qbtc/x/qbtc/types"
	storetypes "github.com/cosmos/cosmos-sdk/store/v2/types"
	sdk "github.com/cosmos/cosmos-sdk/types"

	se "github.com/cosmos/cosmos-sdk/types/errors"
)

type InjectedTxDecorator struct{}

func NewInjectedTxDecorator() InjectedTxDecorator {
	return InjectedTxDecorator{}
}

// AnteHandle is the ante handler for the injected tx decorator
// checks that enshired txs should only be allowed via proposal inject tx
// and not through regular tx flow.
func (itd InjectedTxDecorator) AnteHandle(ctx sdk.Context, tx sdk.Tx, simulate bool, next sdk.AnteHandler) (newCtx sdk.Context, err error) {
	if _, ok := tx.(wInjectTx); !ok {
		for _, m := range tx.GetMsgs() {
			switch m.(type) {
			case *types.MsgBtcBlock:
				// only allowed through an InjectTx, fail.
				return ctx, se.ErrUnauthorized.Wrap(fmt.Sprintf("msg only allowed via proposal inject tx: %T", m))
			default:
				// proceed
			}
		}

		return next(ctx, tx, simulate)
	}

	// only allow if we are in deliver tx (only way is via proposer injected tx)
	if ctx.IsCheckTx() || ctx.IsReCheckTx() || simulate {
		return ctx, se.ErrUnauthorized.Wrap("inject txs only allowed via proposal")
	}

	msgs := tx.GetMsgs()

	if len(msgs) != 1 {
		return ctx, se.ErrUnauthorized.Wrap("inject txs only allowed with 1 msg")
	}

	// make sure entire tx is only allowed msgs
	for _, m := range msgs {
		switch m.(type) {
		case *types.MsgBtcBlock:
			// allowed
		default:
			return ctx, se.ErrUnauthorized.Wrap(fmt.Sprintf("invalid inject tx message type: %T", m))
		}
	}

	// The block's max_gas is for user transactions: PrepareProposal and
	// ProcessProposal leave the inject tx out of it, and its size is bounded by
	// types.MaxBtcBlocksPerMsg. The SDK's block gas meter is off by default; if
	// it is turned on, baseapp charges the tx's gas to the block gas meter of the
	// context returned here, so a meter of its own keeps a batch of Bitcoin
	// blocks from using up the block.
	//
	// skip rest of antes
	return ctx.WithBlockGasMeter(storetypes.NewInfiniteGasMeter()), nil
}
