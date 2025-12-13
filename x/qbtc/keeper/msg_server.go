package keeper

import (
	"github.com/btcq-org/qbtc/x/qbtc/types"
)

type msgServer struct {
	k *Keeper
}

// NewMsgServerImpl returns an implementation of the MsgServer interface
// for the provided Keeper.
func NewMsgServerImpl(k *Keeper) types.MsgServer {
	return &msgServer{
		k: k,
	}
}

var _ types.MsgServer = &msgServer{}
