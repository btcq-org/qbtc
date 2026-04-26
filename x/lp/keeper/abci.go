package keeper

import (
	"context"

	"cosmossdk.io/math"
	sdk "github.com/cosmos/cosmos-sdk/types"

	"github.com/btcq-org/qbtc/x/lp/types"
)

// EndBlock sweeps expired pending adds and refunds the locked qbtc to the
// node operator. BTC arriving for an already-expired pending will be parked in
// the secured holding account by x/secured (we do not auto-refund BTC here).
func (k *Keeper) EndBlock(ctx context.Context) error {
	height := sdk.UnwrapSDKContext(ctx).BlockHeight()
	return k.PendingAdds.Walk(ctx, nil, func(id uint64, pa types.PendingAdd) (bool, error) {
		if pa.Status != types.PendingStatus_PENDING_STATUS_OPEN {
			return false, nil
		}
		if pa.ExpiresAtHeight > height {
			return false, nil
		}

		// Refund the locked qbtc back to the node operator.
		nodeAddr, err := sdk.AccAddressFromBech32(pa.NodeId)
		if err != nil {
			return false, err
		}
		if !pa.QbtcLocked.IsZero() {
			if err := k.bankKeeper.SendCoinsFromModuleToAccount(
				ctx, types.ModuleName, nodeAddr,
				sdk.NewCoins(sdk.NewCoin(types.DenomQbtc, math.NewIntFromBigInt(pa.QbtcLocked.BigInt()))),
			); err != nil {
				return false, err
			}
		}

		pool := k.MustGetPool(ctx)
		pool.PendingInboundQbtc = subSafe(pool.PendingInboundQbtc, pa.QbtcLocked)
		if err := k.SetPool(ctx, pool); err != nil {
			return false, err
		}

		if err := k.closePending(ctx, &pa, types.PendingStatus_PENDING_STATUS_EXPIRED); err != nil {
			return false, err
		}

		sdk.UnwrapSDKContext(ctx).EventManager().EmitEvent(
			sdk.NewEvent("lp_pending_expired",
				sdk.NewAttribute("pending_id", uintString(id)),
				sdk.NewAttribute("node_id", pa.NodeId),
				sdk.NewAttribute("qbtc_refunded", pa.QbtcLocked.String()),
			),
		)
		return false, nil
	})
}
