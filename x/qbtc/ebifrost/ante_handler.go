package ebifrost

import (
	"fmt"

	sdk "github.com/cosmos/cosmos-sdk/types"

	se "github.com/cosmos/cosmos-sdk/types/errors"
)

type InjectedTxDecorator struct{}

func NewInjectedTxDecorator() InjectedTxDecorator {
	return InjectedTxDecorator{}
}

func (itd InjectedTxDecorator) AnteHandle(ctx sdk.Context, tx sdk.Tx, simulate bool, next sdk.AnteHandler) (newCtx sdk.Context, err error) {
	if _, ok := tx.(wInjectTx); !ok {
		for _, m := range tx.GetMsgs() {
			switch m.(type) {
			// TODO: handle utxo injection
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
		// TODO: handle utxo injection
		default:
			return ctx, se.ErrUnauthorized.Wrap(fmt.Sprintf("invalid inject tx message type: %T", m))
		}
	}

	// skip rest of antes
	return ctx, nil
}
