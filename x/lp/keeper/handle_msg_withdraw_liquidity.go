package keeper

import (
	"context"

	"cosmossdk.io/math"
	sdk "github.com/cosmos/cosmos-sdk/types"
	se "github.com/cosmos/cosmos-sdk/types/errors"

	securedtypes "github.com/btcq-org/qbtc/x/secured/types"

	"github.com/btcq-org/qbtc/x/lp/types"
)

// WithdrawLiquidity burns a basis-points fraction of the signer's *free*
// lp/btc-qbtc balance and pays out qbtc on-chain plus an L1 BTC outbound to
// the LP record's locked btc_address. Bonded units physically live in the
// lp_bonded module account and are not in the signer's bank balance, so
// "free" is exactly what the signer holds — no extra check is needed.
func (s *msgServer) WithdrawLiquidity(
	ctx context.Context,
	msg *types.MsgWithdrawLiquidity,
) (*types.MsgWithdrawLiquidityResponse, error) {
	if err := msg.ValidateBasic(); err != nil {
		return nil, err
	}
	if msg.Signer != msg.NodeId {
		return nil, types.ErrSignerNotNode.Wrapf(
			"signer %s != node_id %s", msg.Signer, msg.NodeId)
	}

	signer, err := sdk.AccAddressFromBech32(msg.Signer)
	if err != nil {
		return nil, se.ErrInvalidAddress.Wrap(err.Error())
	}

	// Look up the BTC withdraw destination from the LP record. Established
	// on the first add and immutable thereafter.
	lp, err := s.k.LPs.Get(ctx, msg.NodeId)
	if err != nil {
		return nil, types.ErrLPNotFound.Wrap(msg.NodeId)
	}
	if lp.BtcAddress == "" {
		return nil, types.ErrLPNotFound.Wrapf("%s has no btc_address binding", msg.NodeId)
	}

	freeUnitsInt := s.k.bankKeeper.GetBalance(ctx, signer, types.DenomLPUnit).Amount
	if freeUnitsInt.IsZero() {
		return nil, types.ErrLPNotFound.Wrapf("%s has zero free units", msg.NodeId)
	}
	freeUnits := math.NewUintFromBigInt(freeUnitsInt.BigInt())

	pool := s.k.MustGetPool(ctx)
	btcOut, qbtcOut, unitsBurned, err := types.CalcWithdrawAmounts(
		freeUnits, uint64(msg.BasisPoints), pool.PoolUnits, pool.BalanceSbtc, pool.BalanceQbtc,
	)
	if err != nil {
		return nil, err
	}

	// Pull units from signer to lp module and burn.
	burnCoin := sdk.NewCoin(types.DenomLPUnit, math.NewIntFromBigInt(unitsBurned.BigInt()))
	if err := s.k.bankKeeper.SendCoinsFromAccountToModule(
		ctx, signer, types.ModuleName, sdk.NewCoins(burnCoin),
	); err != nil {
		return nil, err
	}
	if err := s.k.bankKeeper.BurnCoins(ctx, types.ModuleName, sdk.NewCoins(burnCoin)); err != nil {
		return nil, err
	}

	// Pay qbtc to the signer on-chain.
	if !qbtcOut.IsZero() {
		if err := s.k.bankKeeper.SendCoinsFromModuleToAccount(
			ctx, types.ModuleName, signer,
			sdk.NewCoins(sdk.NewCoin(types.DenomQbtc, math.NewIntFromBigInt(qbtcOut.BigInt()))),
		); err != nil {
			return nil, err
		}
	}

	// Move sbtc lp -> secured and queue the L1 outbound to the LP's BTC
	// address.
	var txOutID uint64
	if !btcOut.IsZero() {
		if err := s.k.bankKeeper.SendCoinsFromModuleToModule(
			ctx, types.ModuleName, securedtypes.ModuleName,
			sdk.NewCoins(sdk.NewCoin(securedtypes.DenomSecuredBTC, math.NewIntFromBigInt(btcOut.BigInt()))),
		); err != nil {
			return nil, err
		}
		txOutID, err = s.k.securedKeeper.BurnSecuredAndQueueOutbound(
			ctx, btcOut, lp.BtcAddress, "out:"+msg.NodeId, msg.NodeId,
		)
		if err != nil {
			return nil, err
		}
	}

	applyWithdraw(&pool, btcOut, qbtcOut, unitsBurned)
	if err := s.k.SetPool(ctx, pool); err != nil {
		return nil, err
	}

	sdk.UnwrapSDKContext(ctx).EventManager().EmitEvent(
		sdk.NewEvent("lp_withdraw",
			sdk.NewAttribute("node_id", msg.NodeId),
			sdk.NewAttribute("basis_points", uintString(uint64(msg.BasisPoints))),
			sdk.NewAttribute("units_burned", unitsBurned.String()),
			sdk.NewAttribute("btc_out", btcOut.String()),
			sdk.NewAttribute("qbtc_out", qbtcOut.String()),
			sdk.NewAttribute("tx_out_id", uintString(txOutID)),
		),
	)
	return &types.MsgWithdrawLiquidityResponse{
		QbtcOut: qbtcOut.String(),
		SbtcOut: btcOut.String(),
		TxOutId: txOutID,
	}, nil
}
