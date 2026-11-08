package keeper

import (
	"context"
	"errors"
	"strconv"

	"cosmossdk.io/collections"
	sdkmath "cosmossdk.io/math"
	"github.com/btcq-org/qbtc/constants"
	"github.com/btcq-org/qbtc/x/qbtc/types"
	sdk "github.com/cosmos/cosmos-sdk/types"
)

// referralReward returns bps basis points of amount, rounded down. Rounding
// down means splitting a claim never earns more than claiming at once.
func referralReward(amount uint64, bps int64) sdkmath.Int {
	if bps <= 0 {
		return sdkmath.ZeroInt()
	}
	if bps > constants.MaxRewardBps {
		bps = constants.MaxRewardBps
	}
	return sdkmath.NewIntFromUint64(amount).MulRaw(bps).QuoRaw(constants.MaxRewardBps)
}

// GetReferralStats returns the referral totals of addr, all zero when it has
// none.
func (k Keeper) GetReferralStats(ctx context.Context, addr sdk.AccAddress) (types.ReferralStats, error) {
	stats, err := k.ReferralStats.Get(ctx, addr)
	if errors.Is(err, collections.ErrNotFound) {
		return types.ReferralStats{Address: addr.String()}, nil
	}
	return stats, err
}

// ReferralPoolBalance returns the referral pool balance in the bond denom.
func (k Keeper) ReferralPoolBalance(ctx context.Context) sdkmath.Int {
	return k.GetBalanceOfModule(ctx, types.ReferralModuleName, sdk.DefaultBondDenom).Amount
}

// applyReferral records a claim of amount that named referrer and was sent to
// referee, then pays the rewards from the referral pool. A reward that the
// pool cannot cover is cut to the balance and nothing is owed afterwards. It
// never fails the claim: an error is logged and the referral is dropped.
func (k Keeper) applyReferral(ctx sdk.Context, referrer, referee sdk.AccAddress, amount uint64) {
	cacheCtx, write := ctx.CacheContext()
	referrerReward, refereeReward, err := k.payReferral(cacheCtx, referrer, referee, amount)
	if err != nil {
		ctx.Logger().Error("failed to apply referral", "referrer", referrer.String(), "referee", referee.String(), "error", err)
		return
	}
	write()

	ctx.EventManager().EmitEvent(sdk.NewEvent(
		types.EventTypeReferralReward,
		sdk.NewAttribute(types.AttributeKeyReferrer, referrer.String()),
		sdk.NewAttribute(types.AttributeKeyReferee, referee.String()),
		sdk.NewAttribute(types.AttributeKeyClaimedAmount, strconv.FormatUint(amount, 10)),
		sdk.NewAttribute(types.AttributeKeyReferrerReward, referrerReward.String()),
		sdk.NewAttribute(types.AttributeKeyRefereeReward, refereeReward.String()),
		sdk.NewAttribute(types.AttributeKeyPoolBalance, k.ReferralPoolBalance(ctx).String()),
	))
}

func (k Keeper) payReferral(ctx sdk.Context, referrer, referee sdk.AccAddress, amount uint64) (sdkmath.Int, sdkmath.Int, error) {
	pool := k.ReferralPoolBalance(ctx)
	referrerReward := sdkmath.MinInt(referralReward(amount, k.GetConfig(ctx, constants.ReferrerRewardBps)), pool)
	pool = pool.Sub(referrerReward)
	refereeReward := sdkmath.MinInt(referralReward(amount, k.GetConfig(ctx, constants.RefereeRewardBps)), pool)

	referrerStats, err := k.GetReferralStats(ctx, referrer)
	if err != nil {
		return sdkmath.Int{}, sdkmath.Int{}, err
	}
	referrerStats.ReferredClaims++
	referrerStats.ReferredAmount += amount
	referrerStats.ReferrerRewardsPaid += referrerReward.Uint64()
	if err := k.ReferralStats.Set(ctx, referrer, referrerStats); err != nil {
		return sdkmath.Int{}, sdkmath.Int{}, err
	}
	if err := k.sendReferralReward(ctx, referrer, referrerReward); err != nil {
		return sdkmath.Int{}, sdkmath.Int{}, err
	}

	if refereeReward.IsPositive() {
		refereeStats, err := k.GetReferralStats(ctx, referee)
		if err != nil {
			return sdkmath.Int{}, sdkmath.Int{}, err
		}
		refereeStats.RefereeRewardsPaid += refereeReward.Uint64()
		if err := k.ReferralStats.Set(ctx, referee, refereeStats); err != nil {
			return sdkmath.Int{}, sdkmath.Int{}, err
		}
		if err := k.sendReferralReward(ctx, referee, refereeReward); err != nil {
			return sdkmath.Int{}, sdkmath.Int{}, err
		}
	}
	return referrerReward, refereeReward, nil
}

func (k Keeper) sendReferralReward(ctx context.Context, to sdk.AccAddress, amount sdkmath.Int) error {
	if !amount.IsPositive() {
		return nil
	}
	coins := sdk.NewCoins(sdk.NewCoin(sdk.DefaultBondDenom, amount))
	return k.bankKeeper.SendCoinsFromModuleToAccount(ctx, types.ReferralModuleName, to, coins)
}
