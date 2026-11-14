package keeper

import (
	"context"

	"github.com/btcq-org/qbtc/constants"
	"github.com/btcq-org/qbtc/x/qbtc/types"
	sdk "github.com/cosmos/cosmos-sdk/types"
	sdkerrors "github.com/cosmos/cosmos-sdk/types/errors"
)

// ReferralStats returns the referral totals of an address.
func (qs queryServer) ReferralStats(ctx context.Context, req *types.QueryReferralStatsRequest) (*types.QueryReferralStatsResponse, error) {
	if req == nil {
		return nil, sdkerrors.ErrInvalidRequest.Wrap("empty request")
	}
	addr, err := sdk.AccAddressFromBech32(req.Address)
	if err != nil {
		return nil, sdkerrors.ErrInvalidAddress.Wrapf("invalid address: %v", err)
	}
	stats, err := qs.k.GetReferralStats(ctx, addr)
	if err != nil {
		return nil, err
	}
	return &types.QueryReferralStatsResponse{Stats: stats}, nil
}

// ReferralPool returns the referral pool balance and the reward rates.
func (qs queryServer) ReferralPool(ctx context.Context, _ *types.QueryReferralPoolRequest) (*types.QueryReferralPoolResponse, error) {
	sdkCtx := sdk.UnwrapSDKContext(ctx)
	return &types.QueryReferralPoolResponse{
		Balance:           qs.k.ReferralPoolBalance(ctx).Uint64(),
		ReferrerRewardBps: qs.k.GetConfig(sdkCtx, constants.ReferrerRewardBps),
		RefereeRewardBps:  qs.k.GetConfig(sdkCtx, constants.RefereeRewardBps),
	}, nil
}
