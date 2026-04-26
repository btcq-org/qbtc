package keeper

import (
	"context"

	sdk "github.com/cosmos/cosmos-sdk/types"

	"github.com/btcq-org/qbtc/x/secured/types"
)

// EndBlock advances the outbound queue. It does not move funds — bifrost
// signs and broadcasts off-chain — but it transitions queue items between
// states and emits events the signer set listens for, plus retries stuck
// items.
//
// Behavior is intentionally a no-op when OutboundEnabled is false so the LP
// state machine can be exercised end-to-end with mocked observations before
// the bifrost outbound pipeline lands.
func (k *Keeper) EndBlock(ctx context.Context) error {
	if !k.OutboundEnabled(ctx) {
		return nil
	}
	sdkCtx := sdk.UnwrapSDKContext(ctx)
	height := sdkCtx.BlockHeight()

	maxDispatch := k.GetParam(ctx, types.ParamMaxOutboundDispatchPerBlock)
	stuckBlocks := k.GetParam(ctx, types.ParamOutboundStuckBlocks)
	maxRetries := k.GetParam(ctx, types.ParamMaxOutboundRetries)

	dispatched := int64(0)
	return k.TxOutQueue.Walk(ctx, nil, func(id uint64, item types.TxOutItem) (bool, error) {
		switch item.Status {
		case types.OutboundStatus_OUTBOUND_STATUS_QUEUED:
			if dispatched >= maxDispatch {
				return true, nil
			}
			item.Status = types.OutboundStatus_OUTBOUND_STATUS_SIGNING
			if err := k.TxOutQueue.Set(ctx, id, item); err != nil {
				return false, err
			}
			sdkCtx.EventManager().EmitEvent(
				sdk.NewEvent("secured_outbound_dispatched",
					sdk.NewAttribute("id", uintString(id)),
					sdk.NewAttribute("destination", item.Destination),
					sdk.NewAttribute("amount", item.AmountSats.String()),
				),
			)
			dispatched++

		case types.OutboundStatus_OUTBOUND_STATUS_SIGNING,
			types.OutboundStatus_OUTBOUND_STATUS_BROADCAST:
			if stuckBlocks > 0 && height-item.CreatedHeight > stuckBlocks {
				item.RetryCount++
				if int64(item.RetryCount) > maxRetries {
					item.Status = types.OutboundStatus_OUTBOUND_STATUS_FAILED
					sdkCtx.EventManager().EmitEvent(
						sdk.NewEvent("secured_outbound_failed",
							sdk.NewAttribute("id", uintString(id)),
							sdk.NewAttribute("retry_count", uintString(uint64(item.RetryCount))),
						),
					)
				} else {
					// Re-emit the dispatch event so signers can pick it back up.
					item.Status = types.OutboundStatus_OUTBOUND_STATUS_QUEUED
					sdkCtx.EventManager().EmitEvent(
						sdk.NewEvent("secured_outbound_retry",
							sdk.NewAttribute("id", uintString(id)),
							sdk.NewAttribute("retry_count", uintString(uint64(item.RetryCount))),
						),
					)
				}
				if err := k.TxOutQueue.Set(ctx, id, item); err != nil {
					return false, err
				}
			}
		}
		return false, nil
	})
}
