package keeper

import (
	"context"
	"strconv"
	"strings"

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
	// add event
	sdkCtx.EventManager().EmitEvent(
		sdk.NewEvent(
			types.EventTypeGovClaimUTXO,
			sdk.NewAttribute(types.AttributeKeyUTXOCount, strconv.FormatInt(int64(len(msg.Utxos)), 10)),
			sdk.NewAttribute(types.AttributeUtxos, strings.Join(msg.GetUtxoString(), ",")),
		),
	)
	sdkCtx.Logger().Info("governance claimed UTXOs", "claimer", msg.Authority, "count", len(msg.Utxos))
	return &types.MsgEmpty{}, nil
}
