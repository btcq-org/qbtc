package keeper

import (
	"context"

	"cosmossdk.io/math"
	sdk "github.com/cosmos/cosmos-sdk/types"

	"github.com/btcq-org/qbtc/x/secured/types"
)

// MintSecured mints `amount` sats worth of sbtc to the holding account. The
// caller (typically MsgObservedTxIn handler after quorum + dedup) is
// responsible for routing the freshly-minted coins onward (to x/lp on a swap-in
// or add-liquidity match) within the same tx so they don't accumulate in the
// holding account.
//
// refID is recorded for auditability via emitted events; it does not gate the
// mint itself.
func (k *Keeper) MintSecured(ctx context.Context, amount math.Uint, refID string) error {
	if amount.IsZero() {
		return nil
	}
	coin := sdk.NewCoin(types.DenomSecuredBTC, math.NewIntFromBigInt(amount.BigInt()))
	if err := k.bankKeeper.MintCoins(ctx, types.ModuleName, sdk.NewCoins(coin)); err != nil {
		return err
	}
	// Move minted sbtc from the secured module account to the buffer holding
	// account so callers can pull from a stable address.
	if err := k.bankKeeper.SendCoinsFromModuleToModule(
		ctx, types.ModuleName, types.HoldingAccountName, sdk.NewCoins(coin),
	); err != nil {
		return err
	}
	sdk.UnwrapSDKContext(ctx).EventManager().EmitEvent(
		sdk.NewEvent("secured_mint",
			sdk.NewAttribute("amount", amount.String()),
			sdk.NewAttribute("ref_id", refID),
		),
	)
	return nil
}

// BurnSecuredAndQueueOutbound burns `amount` sats worth of sbtc from the
// caller's module account and enqueues a corresponding BTC outbound TxOutItem
// targeted at destBTCAddress. The returned id is the queue entry's id.
//
// The burn is from the secured module account: the caller (x/lp) must have
// already moved sbtc into the secured module via SendCoinsFromModuleToModule
// before calling, OR we accept an explicit "from module" parameter. To keep
// the surface narrow and guarantee accounting, callers transfer first.
func (k *Keeper) BurnSecuredAndQueueOutbound(
	ctx context.Context,
	amount math.Uint,
	destBTCAddress, memo, refID string,
) (uint64, error) {
	if amount.IsZero() {
		return 0, nil
	}

	coin := sdk.NewCoin(types.DenomSecuredBTC, math.NewIntFromBigInt(amount.BigInt()))
	if err := k.bankKeeper.BurnCoins(ctx, types.ModuleName, sdk.NewCoins(coin)); err != nil {
		return 0, err
	}

	id, err := k.TxOutSeq.Next(ctx)
	if err != nil {
		return 0, err
	}
	id++ // Sequence starts at 0; queue ids start at 1 so 0 stays a sentinel.

	sdkCtx := sdk.UnwrapSDKContext(ctx)
	item := types.TxOutItem{
		Id:            id,
		Destination:   destBTCAddress,
		AmountSats:    amount,
		Memo:          memo,
		Reason:        types.OutboundReason_OUTBOUND_REASON_UNSPECIFIED,
		RefId:         refID,
		Status:        types.OutboundStatus_OUTBOUND_STATUS_QUEUED,
		CreatedHeight: sdkCtx.BlockHeight(),
	}
	if err := k.TxOutQueue.Set(ctx, id, item); err != nil {
		return 0, err
	}
	sdkCtx.EventManager().EmitEvent(
		sdk.NewEvent("secured_outbound_queued",
			sdk.NewAttribute("id", uintString(id)),
			sdk.NewAttribute("destination", destBTCAddress),
			sdk.NewAttribute("amount", amount.String()),
			sdk.NewAttribute("ref_id", refID),
		),
	)
	return id, nil
}

func uintString(v uint64) string {
	if v == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	for v > 0 {
		i--
		buf[i] = byte('0' + v%10)
		v /= 10
	}
	return string(buf[i:])
}
