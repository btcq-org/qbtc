package keeper

import (
	"context"

	"cosmossdk.io/math"
	sdk "github.com/cosmos/cosmos-sdk/types"
	se "github.com/cosmos/cosmos-sdk/types/errors"

	securedtypes "github.com/btcq-org/qbtc/x/secured/types"

	"github.com/btcq-org/qbtc/x/lp/types"
)

// WithdrawLiquidity burns a basis-points fraction of the caller's free
// (non-bonded) units and pays out qbtc on-chain plus an L1 BTC outbound to the
// LP's already-proven btc_address.
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

	lp, err := s.k.LPs.Get(ctx, msg.NodeId)
	if err != nil {
		return nil, types.ErrLPNotFound.Wrap(msg.NodeId)
	}
	if lp.Units.IsZero() {
		return nil, types.ErrLPNotFound.Wrapf("%s has zero units", msg.NodeId)
	}

	free, err := s.k.FreeUnits(ctx, msg.NodeId)
	if err != nil {
		return nil, err
	}

	pool := s.k.MustGetPool(ctx)
	btcOut, qbtcOut, unitsBurned, err := types.CalcWithdrawAmounts(
		lp.Units, uint64(msg.BasisPoints), pool.PoolUnits, pool.BalanceSbtc, pool.BalanceQbtc,
	)
	if err != nil {
		return nil, err
	}
	if unitsBurned.GT(free) {
		return nil, types.ErrBondLockedWithdraw.Wrapf(
			"requested burn %s exceeds free units %s; unbond first",
			unitsBurned, free)
	}

	// Pay qbtc to the signer on-chain.
	signer, err := sdk.AccAddressFromBech32(msg.Signer)
	if err != nil {
		return nil, se.ErrInvalidAddress.Wrap(err.Error())
	}
	if !qbtcOut.IsZero() {
		if err := s.k.bankKeeper.SendCoinsFromModuleToAccount(
			ctx, types.ModuleName, signer,
			sdk.NewCoins(sdk.NewCoin(types.DenomQbtc, math.NewIntFromBigInt(qbtcOut.BigInt()))),
		); err != nil {
			return nil, err
		}
	}

	// Burn LP's sbtc share via secured module: move sbtc lp -> secured first.
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

	lp.Units = lp.Units.Sub(unitsBurned)
	if lp.Units.IsZero() {
		if err := s.k.LPs.Remove(ctx, lp.NodeId); err != nil {
			return nil, err
		}
	} else {
		if err := s.k.SetLP(ctx, lp); err != nil {
			return nil, err
		}
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
		QbtcOut:  qbtcOut.String(),
		SbtcOut:  btcOut.String(),
		TxOutId:  txOutID,
	}, nil
}
