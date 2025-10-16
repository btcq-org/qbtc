package keeper

import (
	"context"

	"github.com/btcq-org/btcq/x/btcq/types"
)

type msgServer struct {
	Keeper
}

func (k msgServer) Mimir(ctx context.Context, mimir *types.MsgMimir) (*types.MsgEmpty, error) {
	panic("implement me")
}

// NewMsgServerImpl returns an implementation of the MsgServer interface
// for the provided Keeper.
func NewMsgServerImpl(keeper Keeper) types.MsgServer {
	return &msgServer{Keeper: keeper}
}

var _ types.MsgServer = msgServer{}
