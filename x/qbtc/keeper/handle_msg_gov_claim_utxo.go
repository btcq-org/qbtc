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
	if err := msg.ValidateBasic(); err != nil {
		return nil, err
	}
	if msg.Authority != s.k.GetAuthority() {
		return nil, sdkerror.ErrUnauthorized.Wrap("unauthorized")
	}

	// Resolve optional fund addresses from governance string params.
	var devAddr, mktAddr sdk.AccAddress
	devAddrStr, err := s.k.GetStringParam(ctx, types.DevFundAddressKey)
	if err != nil {
		return nil, err
	}
	if devAddrStr != "" {
		parsed, err := sdk.AccAddressFromBech32(devAddrStr)
		if err != nil {
			return nil, sdkerror.ErrInvalidAddress.Wrapf("invalid dev fund address in params: %s", err)
		}
		devAddr = parsed
	}
	mktAddrStr, err := s.k.GetStringParam(ctx, types.MarketingFundAddressKey)
	if err != nil {
		return nil, err
	}
	if mktAddrStr != "" {
		parsed, err := sdk.AccAddressFromBech32(mktAddrStr)
		if err != nil {
			return nil, sdkerror.ErrInvalidAddress.Wrapf("invalid marketing fund address in params: %s", err)
		}
		mktAddr = parsed
	}

	sdkCtx := sdk.UnwrapSDKContext(ctx)
	cacheCtx, write := sdkCtx.CacheContext()

	var totalDev, totalMkt, totalReserve uint64
	for _, utxo := range msg.Utxos {
		dev, mkt, reserve, err := s.k.GovClaimUTXO(cacheCtx, utxo.Txid, utxo.Vout, devAddr, mktAddr)
		if err != nil {
			return nil, err
		}
		totalDev += dev
		totalMkt += mkt
		totalReserve += reserve
	}
	write()

	sdkCtx.EventManager().EmitEvent(
		sdk.NewEvent(
			types.EventTypeGovClaimUTXO,
			sdk.NewAttribute(types.AttributeKeyUTXOCount, strconv.FormatInt(int64(len(msg.Utxos)), 10)),
			sdk.NewAttribute(types.AttributeUtxos, strings.Join(msg.GetUtxoString(), ",")),
			sdk.NewAttribute(types.AttributeKeyDevFundAmount, strconv.FormatUint(totalDev, 10)),
			sdk.NewAttribute(types.AttributeKeyMarketingFundAmount, strconv.FormatUint(totalMkt, 10)),
			sdk.NewAttribute(types.AttributeKeyReserveAmount, strconv.FormatUint(totalReserve, 10)),
		),
	)
	sdkCtx.Logger().Info("governance claimed UTXOs", "claimer", msg.Authority, "count", len(msg.Utxos))
	return &types.MsgEmpty{}, nil
}
