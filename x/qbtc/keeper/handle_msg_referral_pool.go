package keeper

import (
	"context"
	"strconv"

	errorsmod "cosmossdk.io/errors"
	sdkmath "cosmossdk.io/math"
	"github.com/btcq-org/qbtc/x/qbtc/types"
	sdk "github.com/cosmos/cosmos-sdk/types"
	sdkerrors "github.com/cosmos/cosmos-sdk/types/errors"
)

// FundReferralPool moves coins from the reserve to the referral pool.
func (s *msgServer) FundReferralPool(ctx context.Context, msg *types.MsgFundReferralPool) (*types.MsgEmpty, error) {
	if err := msg.ValidateBasic(); err != nil {
		return nil, err
	}
	if err := s.moveReferralPoolFunds(ctx, msg.Authority, types.ReserveModuleName, types.ReferralModuleName, msg.Amount, types.EventTypeFundReferralPool); err != nil {
		return nil, err
	}
	return &types.MsgEmpty{}, nil
}

// DrainReferralPool moves coins from the referral pool back to the reserve.
func (s *msgServer) DrainReferralPool(ctx context.Context, msg *types.MsgDrainReferralPool) (*types.MsgEmpty, error) {
	if err := msg.ValidateBasic(); err != nil {
		return nil, err
	}
	if err := s.moveReferralPoolFunds(ctx, msg.Authority, types.ReferralModuleName, types.ReserveModuleName, msg.Amount, types.EventTypeDrainReferralPool); err != nil {
		return nil, err
	}
	return &types.MsgEmpty{}, nil
}

func (s *msgServer) moveReferralPoolFunds(ctx context.Context, authority, from, to string, amount uint64, eventType string) error {
	if authority != s.k.GetAuthority() {
		return sdkerrors.ErrUnauthorized.Wrap("unauthorized")
	}
	sdkCtx := sdk.UnwrapSDKContext(ctx)
	coins := sdk.NewCoins(sdk.NewCoin(sdk.DefaultBondDenom, sdkmath.NewIntFromUint64(amount)))
	if err := s.k.bankKeeper.SendCoinsFromModuleToModule(sdkCtx, from, to, coins); err != nil {
		return errorsmod.Wrapf(err, "failed to move %s from %s to %s", coins, from, to)
	}
	sdkCtx.EventManager().EmitEvent(sdk.NewEvent(
		eventType,
		sdk.NewAttribute(types.AttributeKeyAmount, strconv.FormatUint(amount, 10)),
		sdk.NewAttribute(types.AttributeKeyPoolBalance, s.k.ReferralPoolBalance(sdkCtx).String()),
	))
	return nil
}
