package keeper

import (
	"context"

	"cosmossdk.io/math"
	sdk "github.com/cosmos/cosmos-sdk/types"
	se "github.com/cosmos/cosmos-sdk/types/errors"

	"github.com/btcq-org/qbtc/x/lp/types"
)

// AddLiquidity opens a symmetric add intent. The qbtc side is locked into the
// lp module account immediately. The BTC side is observed at the vault later
// via x/secured.MsgObservedTxIn (memo `+:<pending_id>`); on observation the
// LPHooks.OnObservedAddLiquidity callback issues units.
//
// btc_address is the future withdraw destination; it is locked on the first
// add and enforced on subsequent adds. No ownership proof is required — a
// node that declares an address they don't control only hurts themselves on
// withdraw, so this is a wallet-UX concern, not a protocol-security one.
func (s *msgServer) AddLiquidity(
	ctx context.Context,
	msg *types.MsgAddLiquidity,
) (*types.MsgAddLiquidityResponse, error) {
	if err := msg.ValidateBasic(); err != nil {
		return nil, err
	}
	if msg.Signer != msg.NodeId {
		// Bond-provider co-funding could legitimately make these differ; for
		// v1 we restrict to the node operator themselves. Lift later.
		return nil, types.ErrSignerNotNode.Wrapf(
			"signer %s != node_id %s; bond-provider adds not yet supported",
			msg.Signer, msg.NodeId)
	}
	if err := s.k.EnsurePoolAvailable(ctx); err != nil {
		return nil, err
	}

	// Lock or verify the LP record's BTC address.
	lp, err := s.k.GetOrInitLP(ctx, msg.NodeId)
	if err != nil {
		return nil, err
	}
	if lp.BtcAddress != "" && lp.BtcAddress != msg.BtcAddress {
		return nil, types.ErrBTCAddressMismatch.Wrapf(
			"existing %s, supplied %s", lp.BtcAddress, msg.BtcAddress)
	}
	if lp.BtcAddress == "" {
		lp.BtcAddress = msg.BtcAddress
		if err := s.k.SetLP(ctx, lp); err != nil {
			return nil, err
		}
	}

	// Pull qbtc from the signer into the lp module account.
	signer, err := sdk.AccAddressFromBech32(msg.Signer)
	if err != nil {
		return nil, se.ErrInvalidAddress.Wrapf("signer: %v", err)
	}
	coin := sdk.NewCoin(types.DenomQbtc, math.NewIntFromBigInt(msg.QbtcAmount.BigInt()))
	if err := s.k.bankKeeper.SendCoinsFromAccountToModule(
		ctx, signer, types.ModuleName, sdk.NewCoins(coin),
	); err != nil {
		return nil, err
	}

	// Account the locked qbtc on the pool's pending counter so pool invariants
	// remain consistent before the BTC side arrives.
	pool := s.k.MustGetPool(ctx)
	pool.PendingInboundQbtc = pool.PendingInboundQbtc.Add(msg.QbtcAmount)
	if err := s.k.SetPool(ctx, pool); err != nil {
		return nil, err
	}

	tolerance := uint32(s.k.GetParam(ctx, types.ParamPendingAddToleranceBps))
	pa, err := s.k.CreatePending(ctx, msg.NodeId, msg.BtcAddress, msg.QbtcAmount, msg.BtcAmountDeclared, tolerance)
	if err != nil {
		return nil, err
	}

	sdk.UnwrapSDKContext(ctx).EventManager().EmitEvent(
		sdk.NewEvent("lp_add_liquidity_pending",
			sdk.NewAttribute("pending_id", uintString(pa.Id)),
			sdk.NewAttribute("node_id", msg.NodeId),
			sdk.NewAttribute("qbtc_locked", msg.QbtcAmount.String()),
			sdk.NewAttribute("btc_expected", msg.BtcAmountDeclared.String()),
			sdk.NewAttribute("expires_at_height", intString(pa.ExpiresAtHeight)),
		),
	)
	return &types.MsgAddLiquidityResponse{PendingAddId: pa.Id}, nil
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

func intString(v int64) string {
	if v == 0 {
		return "0"
	}
	neg := v < 0
	if neg {
		v = -v
	}
	var buf [20]byte
	i := len(buf)
	for v > 0 {
		i--
		buf[i] = byte('0' + byte(v%10))
		v /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}
