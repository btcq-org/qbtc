package keeper

import (
	"context"

	"cosmossdk.io/math"
	sdk "github.com/cosmos/cosmos-sdk/types"
	se "github.com/cosmos/cosmos-sdk/types/errors"

	securedtypes "github.com/btcq-org/qbtc/x/secured/types"

	"github.com/btcq-org/qbtc/x/lp/types"
)

// Swap executes one of three on-chain swap pairs. The fourth (BTC L1 -> qbtc)
// is memo-driven via x/secured.MsgObservedTxIn and routed through
// LPHooks.OnObservedSwapToQbtc.
//
// Pairs:
//
//	qbtc -> sbtc   (purely on-chain)
//	qbtc -> btc    (queues a vault outbound; dest_address is BTC bech32)
//	sbtc -> qbtc   (purely on-chain)
func (s *msgServer) Swap(
	ctx context.Context,
	msg *types.MsgSwap,
) (*types.MsgSwapResponse, error) {
	if err := msg.ValidateBasic(); err != nil {
		return nil, err
	}
	if err := s.k.EnsurePoolAvailable(ctx); err != nil {
		return nil, err
	}

	signer, err := sdk.AccAddressFromBech32(msg.Signer)
	if err != nil {
		return nil, se.ErrInvalidAddress.Wrap(err.Error())
	}

	switch {
	case msg.SourceDenom == types.DenomQbtc && msg.DestDenom == types.DenomSecuredBTC:
		return s.swapQbtcToSbtc(ctx, signer, msg)
	case msg.SourceDenom == types.DenomQbtc && msg.DestDenom == "btc":
		return s.swapQbtcToL1(ctx, signer, msg)
	case msg.SourceDenom == types.DenomSecuredBTC && msg.DestDenom == types.DenomQbtc:
		return s.swapSbtcToQbtc(ctx, signer, msg)
	default:
		return nil, types.ErrInvalidPair.Wrapf("%s -> %s", msg.SourceDenom, msg.DestDenom)
	}
}

func (s *msgServer) swapQbtcToSbtc(ctx context.Context, signer sdk.AccAddress, msg *types.MsgSwap) (*types.MsgSwapResponse, error) {
	pool := s.k.MustGetPool(ctx)
	out, slip, err := s.computeSwap(ctx, msg.Amount, msg.MinOut, pool.BalanceQbtc, pool.BalanceSbtc)
	if err != nil {
		return nil, err
	}

	// Pull qbtc in.
	if err := s.k.bankKeeper.SendCoinsFromAccountToModule(
		ctx, signer, types.ModuleName,
		sdk.NewCoins(sdk.NewCoin(types.DenomQbtc, math.NewIntFromBigInt(msg.Amount.BigInt()))),
	); err != nil {
		return nil, err
	}

	// Pay sbtc out to dest cosmos address.
	dest, err := sdk.AccAddressFromBech32(msg.DestAddress)
	if err != nil {
		return nil, se.ErrInvalidAddress.Wrap(err.Error())
	}
	if err := s.k.bankKeeper.SendCoinsFromModuleToAccount(
		ctx, types.ModuleName, dest,
		sdk.NewCoins(sdk.NewCoin(securedtypes.DenomSecuredBTC, math.NewIntFromBigInt(out.BigInt()))),
	); err != nil {
		return nil, err
	}

	applySwapInputQBTC(&pool, msg.Amount, out)
	if err := s.k.SetPool(ctx, pool); err != nil {
		return nil, err
	}
	emitSwap(ctx, "qbtc->sbtc", msg.Amount, out, slip, msg.DestAddress, 0)
	return &types.MsgSwapResponse{
		OutAmount: out.String(),
		SlipBps:   uint32(slip.Uint64()),
	}, nil
}

func (s *msgServer) swapQbtcToL1(ctx context.Context, signer sdk.AccAddress, msg *types.MsgSwap) (*types.MsgSwapResponse, error) {
	pool := s.k.MustGetPool(ctx)
	out, slip, err := s.computeSwap(ctx, msg.Amount, msg.MinOut, pool.BalanceQbtc, pool.BalanceSbtc)
	if err != nil {
		return nil, err
	}

	// Pull qbtc in.
	if err := s.k.bankKeeper.SendCoinsFromAccountToModule(
		ctx, signer, types.ModuleName,
		sdk.NewCoins(sdk.NewCoin(types.DenomQbtc, math.NewIntFromBigInt(msg.Amount.BigInt()))),
	); err != nil {
		return nil, err
	}

	// Move sbtc lp -> secured so secured can burn.
	if err := s.k.bankKeeper.SendCoinsFromModuleToModule(
		ctx, types.ModuleName, securedtypes.ModuleName,
		sdk.NewCoins(sdk.NewCoin(securedtypes.DenomSecuredBTC, math.NewIntFromBigInt(out.BigInt()))),
	); err != nil {
		return nil, err
	}
	txOutID, err := s.k.securedKeeper.BurnSecuredAndQueueOutbound(
		ctx, out, msg.DestAddress, "swap:"+msg.Signer, msg.Signer,
	)
	if err != nil {
		return nil, err
	}

	applySwapInputQBTC(&pool, msg.Amount, out)
	if err := s.k.SetPool(ctx, pool); err != nil {
		return nil, err
	}
	emitSwap(ctx, "qbtc->btc", msg.Amount, out, slip, msg.DestAddress, txOutID)
	return &types.MsgSwapResponse{
		OutAmount: out.String(),
		SlipBps:   uint32(slip.Uint64()),
		TxOutId:   txOutID,
	}, nil
}

func (s *msgServer) swapSbtcToQbtc(ctx context.Context, signer sdk.AccAddress, msg *types.MsgSwap) (*types.MsgSwapResponse, error) {
	pool := s.k.MustGetPool(ctx)
	out, slip, err := s.computeSwap(ctx, msg.Amount, msg.MinOut, pool.BalanceSbtc, pool.BalanceQbtc)
	if err != nil {
		return nil, err
	}

	// Pull sbtc in.
	if err := s.k.bankKeeper.SendCoinsFromAccountToModule(
		ctx, signer, types.ModuleName,
		sdk.NewCoins(sdk.NewCoin(securedtypes.DenomSecuredBTC, math.NewIntFromBigInt(msg.Amount.BigInt()))),
	); err != nil {
		return nil, err
	}

	// Pay qbtc out to dest cosmos address.
	dest, err := sdk.AccAddressFromBech32(msg.DestAddress)
	if err != nil {
		return nil, se.ErrInvalidAddress.Wrap(err.Error())
	}
	if err := s.k.bankKeeper.SendCoinsFromModuleToAccount(
		ctx, types.ModuleName, dest,
		sdk.NewCoins(sdk.NewCoin(types.DenomQbtc, math.NewIntFromBigInt(out.BigInt()))),
	); err != nil {
		return nil, err
	}

	applySwapInputBTC(&pool, msg.Amount, out)
	if err := s.k.SetPool(ctx, pool); err != nil {
		return nil, err
	}
	emitSwap(ctx, "sbtc->qbtc", msg.Amount, out, slip, msg.DestAddress, 0)
	return &types.MsgSwapResponse{
		OutAmount: out.String(),
		SlipBps:   uint32(slip.Uint64()),
	}, nil
}

func (s *msgServer) computeSwap(
	ctx context.Context,
	in, minOut, inBal, outBal math.Uint,
) (out math.Uint, slip math.Uint, err error) {
	out, err = types.CalcSwapOutput(in, inBal, outBal)
	if err != nil {
		return math.ZeroUint(), math.ZeroUint(), err
	}
	slip = types.CalcSlipBps(in, inBal)
	maxSlip := uint64(s.k.GetParam(ctx, types.ParamMaxSlipBps))
	if slip.GT(math.NewUint(maxSlip)) {
		return math.ZeroUint(), math.ZeroUint(), types.ErrSlipExceedsLimit
	}
	if out.LT(minOut) {
		return math.ZeroUint(), math.ZeroUint(), types.ErrOutBelowMinimum
	}
	return out, slip, nil
}

func emitSwap(ctx context.Context, kind string, in, out, slip math.Uint, dest string, txOutID uint64) {
	sdk.UnwrapSDKContext(ctx).EventManager().EmitEvent(
		sdk.NewEvent("lp_swap",
			sdk.NewAttribute("kind", kind),
			sdk.NewAttribute("in", in.String()),
			sdk.NewAttribute("out", out.String()),
			sdk.NewAttribute("slip_bps", slip.String()),
			sdk.NewAttribute("dest", dest),
			sdk.NewAttribute("tx_out_id", uintString(txOutID)),
		),
	)
}
