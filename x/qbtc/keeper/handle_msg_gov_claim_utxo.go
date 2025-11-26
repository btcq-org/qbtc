package keeper

import (
	"context"

	"github.com/btcq-org/qbtc/x/qbtc/types"
	sdk "github.com/cosmos/cosmos-sdk/types"
	sdkerror "github.com/cosmos/cosmos-sdk/types/errors"
)

func (s *msgServer) GovClaimUTXO(ctx context.Context, msg *types.MsgGovClaimUTXO) (*types.MsgEmpty, error) {
	// validate the message
	if err := msg.ValidateBasic(); err != nil {
		return nil, err
	}
	if msg.Authority != s.k.GetAuthority() {
		return nil, sdkerror.ErrUnauthorized.Wrap("unauthorized")
	}
	sdkCtx := sdk.UnwrapSDKContext(ctx)
	cacheCtx, write := sdkCtx.CacheContext()
	for _, utxo := range msg.Utxos {
		if err := s.k.ClaimUTXO(cacheCtx, utxo.Txid, utxo.Vout, nil); err != nil {
			return nil, err
		}
	}
	write()
	return &types.MsgEmpty{}, nil
}
