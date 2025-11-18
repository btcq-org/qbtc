package keeper

import (
	"context"

	"github.com/btcq-org/qbtc/x/qbtc/types"
	sdk "github.com/cosmos/cosmos-sdk/types"
	sdkerrors "github.com/cosmos/cosmos-sdk/types/errors"
)

func (s *msgServer) UpdateParam(ctx context.Context, msg *types.MsgUpdateParam) (*types.MsgEmpty, error) {
	if err := msg.ValidateBasic(); err != nil {
		return nil, err
	}
	if msg.Authority != s.k.GetAuthority() {
		return nil, sdkerrors.ErrUnauthorized.Wrap("unauthorized")
	}
	sdkCtx := sdk.UnwrapSDKContext(ctx)
	cacheCtx, write := sdkCtx.CacheContext()
	if err := s.k.ConstOverrides.Set(cacheCtx, msg.Key, msg.Value); err != nil {
		return nil, err
	}
	write()
	return &types.MsgEmpty{}, nil
}
