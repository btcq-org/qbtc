package keeper

import "github.com/btcq-org/qbtc/x/lp/types"

type msgServer struct {
	k *Keeper
}

func NewMsgServerImpl(k *Keeper) types.MsgServer {
	return &msgServer{k: k}
}

var _ types.MsgServer = (*msgServer)(nil)
