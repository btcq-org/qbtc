package keeper

import (
	"context"
	"errors"

	"cosmossdk.io/collections"
	"cosmossdk.io/math"
	sdk "github.com/cosmos/cosmos-sdk/types"

	securedtypes "github.com/btcq-org/qbtc/x/secured/types"

	"github.com/btcq-org/qbtc/x/lp/types"
)

// LPHooks adapts the Keeper to the secured-module LPHooks interface, so
// x/secured can route memo-finalized inbound observations into the LP state
// machine without an import cycle.
type LPHooks struct {
	k *Keeper
}

func NewLPHooks(k *Keeper) LPHooks { return LPHooks{k: k} }

var _ securedtypes.LPHooks = LPHooks{}

// OnObservedAddLiquidity is called by x/secured after MsgObservedTxIn finalizes
// a deposit with memo `+:<pending_id>`. By the time this fires, sbtc has been
// minted to the secured holding account; we pull it forward into the lp
// module account, run the symmetric LP-unit math, and credit the LP.
func (h LPHooks) OnObservedAddLiquidity(
	ctx context.Context,
	pendingID uint64,
	sats math.Uint,
	txid string,
) error {
	pa, err := h.k.PendingAdds.Get(ctx, pendingID)
	if err != nil {
		if errors.Is(err, collections.ErrNotFound) {
			sdk.UnwrapSDKContext(ctx).Logger().Error(
				"observed add for unknown pending id; sbtc parked",
				"pending_id", pendingID, "txid", txid)
			return nil
		}
		return err
	}
	if pa.Status != types.PendingStatus_PENDING_STATUS_OPEN {
		sdk.UnwrapSDKContext(ctx).Logger().Error(
			"observed add for non-open pending; sbtc parked",
			"pending_id", pendingID, "status", pa.Status, "txid", txid)
		return nil
	}
	if !btcWithinTolerance(sats, pa.ExpectedBtc, pa.ToleranceBps) {
		sdk.UnwrapSDKContext(ctx).Logger().Error(
			"observed add outside tolerance; sbtc parked",
			"pending_id", pendingID, "expected", pa.ExpectedBtc.String(),
			"observed", sats.String(), "tolerance_bps", pa.ToleranceBps)
		return nil
	}

	// Move sbtc from secured holding -> lp module so the pool keeper accounts
	// for the new BTC depth.
	if err := h.k.bankKeeper.SendCoinsFromModuleToModule(
		ctx,
		securedtypes.HoldingAccountName,
		types.ModuleName,
		sdk.NewCoins(sdk.NewCoin(securedtypes.DenomSecuredBTC, math.NewIntFromBigInt(sats.BigInt()))),
	); err != nil {
		return err
	}

	pool := h.k.MustGetPool(ctx)
	units, err := types.CalcSymmetricLPUnits(sats, pa.QbtcLocked, pool.BalanceSbtc, pool.BalanceQbtc, pool.PoolUnits)
	if err != nil {
		return err
	}

	applyDeposit(&pool, sats, pa.QbtcLocked, units)
	pool.PendingInboundQbtc = subSafe(pool.PendingInboundQbtc, pa.QbtcLocked)
	if err := h.k.SetPool(ctx, pool); err != nil {
		return err
	}

	// Mint the LP units to the lp module account, then transfer to the node
	// operator's bank account. Free balance of lp/btc-qbtc on the node's
	// account is the source of truth for unit ownership; LiquidityProvider
	// only stores the withdraw-destination binding.
	nodeAddr, err := sdk.AccAddressFromBech32(pa.NodeId)
	if err != nil {
		return err
	}
	unitsCoin := sdk.NewCoin(types.DenomLPUnit, math.NewIntFromBigInt(units.BigInt()))
	if err := h.k.bankKeeper.MintCoins(ctx, types.ModuleName, sdk.NewCoins(unitsCoin)); err != nil {
		return err
	}
	if err := h.k.bankKeeper.SendCoinsFromModuleToAccount(
		ctx, types.ModuleName, nodeAddr, sdk.NewCoins(unitsCoin),
	); err != nil {
		return err
	}

	lp, err := h.k.GetOrInitLP(ctx, pa.NodeId)
	if err != nil {
		return err
	}
	lp.LastAddHeight = sdk.UnwrapSDKContext(ctx).BlockHeight()
	if err := h.k.SetLP(ctx, lp); err != nil {
		return err
	}

	if err := h.k.closePending(ctx, &pa, types.PendingStatus_PENDING_STATUS_MATCHED); err != nil {
		return err
	}

	sdk.UnwrapSDKContext(ctx).EventManager().EmitEvent(
		sdk.NewEvent("lp_add_liquidity_matched",
			sdk.NewAttribute("pending_id", uintString(pendingID)),
			sdk.NewAttribute("node_id", pa.NodeId),
			sdk.NewAttribute("btc_in", sats.String()),
			sdk.NewAttribute("qbtc_in", pa.QbtcLocked.String()),
			sdk.NewAttribute("units_issued", units.String()),
			sdk.NewAttribute("txid", txid),
		),
	)
	return nil
}

// OnObservedSwapToQbtc handles a memo-driven L1 BTC -> qbtc swap. By the time
// this fires sbtc has been minted to the secured holding account.
func (h LPHooks) OnObservedSwapToQbtc(
	ctx context.Context,
	sats math.Uint,
	destCosmosAddr string,
	minOut math.Uint,
	txid, btcSender string,
) error {
	dest, err := sdk.AccAddressFromBech32(destCosmosAddr)
	if err != nil {
		// Bad destination -> refund the sender (via secured outbound) and
		// log. We deduct a fee reserve to cover the BTC tx cost.
		return h.refundInboundSwap(ctx, sats, btcSender, txid, "bad-dest")
	}

	pool := h.k.MustGetPool(ctx)
	if pool.Status != types.PoolStatus_POOL_STATUS_AVAILABLE {
		return h.refundInboundSwap(ctx, sats, btcSender, txid, "pool-unavailable")
	}

	out, err := types.CalcSwapOutput(sats, pool.BalanceSbtc, pool.BalanceQbtc)
	if err != nil {
		return h.refundInboundSwap(ctx, sats, btcSender, txid, "math-error")
	}
	slip := types.CalcSlipBps(sats, pool.BalanceSbtc)
	maxSlip := uint64(h.k.GetParam(ctx, types.ParamMaxSlipBps))
	if slip.GT(math.NewUint(maxSlip)) || out.LT(minOut) {
		return h.refundInboundSwap(ctx, sats, btcSender, txid, "slip-or-min-out")
	}

	// Move sbtc from secured holding -> lp module (pool depth grows).
	if err := h.k.bankKeeper.SendCoinsFromModuleToModule(
		ctx,
		securedtypes.HoldingAccountName,
		types.ModuleName,
		sdk.NewCoins(sdk.NewCoin(securedtypes.DenomSecuredBTC, math.NewIntFromBigInt(sats.BigInt()))),
	); err != nil {
		return err
	}

	// Pay out qbtc from the lp module to the destination.
	if err := h.k.bankKeeper.SendCoinsFromModuleToAccount(
		ctx, types.ModuleName, dest,
		sdk.NewCoins(sdk.NewCoin(types.DenomQbtc, math.NewIntFromBigInt(out.BigInt()))),
	); err != nil {
		return err
	}

	applySwapInputBTC(&pool, sats, out)
	if err := h.k.SetPool(ctx, pool); err != nil {
		return err
	}

	sdk.UnwrapSDKContext(ctx).EventManager().EmitEvent(
		sdk.NewEvent("lp_swap_btc_to_qbtc",
			sdk.NewAttribute("btc_in", sats.String()),
			sdk.NewAttribute("qbtc_out", out.String()),
			sdk.NewAttribute("slip_bps", slip.String()),
			sdk.NewAttribute("dest", destCosmosAddr),
			sdk.NewAttribute("txid", txid),
		),
	)
	return nil
}

// refundInboundSwap returns BTC to the original sender via a secured outbound,
// netting the configured fee reserve. If outbound is disabled the sbtc parks
// in the holding account and operator action is required.
func (h LPHooks) refundInboundSwap(
	ctx context.Context,
	sats math.Uint,
	btcSender, txid, reason string,
) error {
	feeReserve := math.NewUint(uint64(h.k.GetParam(ctx, types.ParamRefundFeeReserveSats)))
	if sats.LTE(feeReserve) {
		// Refund would be zero or negative — keep in holding and alert.
		sdk.UnwrapSDKContext(ctx).Logger().Error(
			"refund below fee reserve; sbtc parked in holding",
			"reason", reason, "sats", sats.String(), "fee_reserve", feeReserve.String(), "txid", txid)
		return nil
	}
	refundAmount := sats.Sub(feeReserve)

	// Move sbtc from secured holding -> secured module (where it can be burnt).
	if err := h.k.bankKeeper.SendCoinsFromModuleToModule(
		ctx,
		securedtypes.HoldingAccountName,
		securedtypes.ModuleName,
		sdk.NewCoins(sdk.NewCoin(securedtypes.DenomSecuredBTC, math.NewIntFromBigInt(refundAmount.BigInt()))),
	); err != nil {
		return err
	}
	// The fee-reserve dust stays in holding. Operator can sweep periodically.

	if !h.k.securedKeeper.OutboundEnabled(ctx) {
		sdk.UnwrapSDKContext(ctx).Logger().Info(
			"outbound disabled; refund queued anyway",
			"reason", reason, "sats", refundAmount.String(), "txid", txid)
	}

	if _, err := h.k.securedKeeper.BurnSecuredAndQueueOutbound(
		ctx, refundAmount, btcSender, "refund:"+txid, txid,
	); err != nil {
		return err
	}
	sdk.UnwrapSDKContext(ctx).EventManager().EmitEvent(
		sdk.NewEvent("lp_swap_refunded",
			sdk.NewAttribute("reason", reason),
			sdk.NewAttribute("amount", refundAmount.String()),
			sdk.NewAttribute("dest", btcSender),
			sdk.NewAttribute("txid", txid),
		),
	)
	return nil
}

// subSafe returns a-b clamped at zero, defending against pending-counter drift.
func subSafe(a, b math.Uint) math.Uint {
	if b.GT(a) {
		return math.ZeroUint()
	}
	return a.Sub(b)
}
