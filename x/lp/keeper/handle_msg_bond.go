package keeper

import (
	"context"

	"cosmossdk.io/math"
	sdk "github.com/cosmos/cosmos-sdk/types"
	se "github.com/cosmos/cosmos-sdk/types/errors"

	"github.com/btcq-org/qbtc/x/lp/types"
)

// Bond moves `units` of lp/btc-qbtc from the caller's bank account into the
// dedicated lp_bonded module account, and credits the per-node Bond record.
// The bank balance on lp_bonded mirrors sum(Bond.UnitsBonded). Bonded units
// are physically inaccessible to the LP from this point — withdraw can only
// burn what the user holds in their own account.
//
// Bond providers (split co-funders) are not supported in v1; the signer must
// equal node_id.
func (s *msgServer) Bond(
	ctx context.Context,
	msg *types.MsgBond,
) (*types.MsgBondResponse, error) {
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

	coin := sdk.NewCoin(types.DenomLPUnit, math.NewIntFromBigInt(msg.Units.BigInt()))
	// Bank rejects this if the signer doesn't have enough free units —
	// that's the protocol's "ErrBondInsufficient" guard, no separate check
	// needed.
	if err := s.k.bankKeeper.SendCoinsFromAccountToModule(
		ctx, signer, types.BondedAccountName, sdk.NewCoins(coin),
	); err != nil {
		return nil, types.ErrBondInsufficient.Wrap(err.Error())
	}

	bond, err := s.k.GetOrInitBond(ctx, msg.NodeId)
	if err != nil {
		return nil, err
	}
	bond.UnitsBonded = bond.UnitsBonded.Add(msg.Units)
	if err := s.k.SetBond(ctx, bond); err != nil {
		return nil, err
	}

	sdk.UnwrapSDKContext(ctx).EventManager().EmitEvent(
		sdk.NewEvent("lp_bond",
			sdk.NewAttribute("node_id", msg.NodeId),
			sdk.NewAttribute("units", msg.Units.String()),
			sdk.NewAttribute("total_bonded", bond.UnitsBonded.String()),
		),
	)
	return &types.MsgBondResponse{}, nil
}

// Unbond moves units from lp_bonded back to the signer's bank account. v1 has
// no churn-state gating; operators can unbond freely. Slashing will tighten
// this in a follow-up.
func (s *msgServer) Unbond(
	ctx context.Context,
	msg *types.MsgUnbond,
) (*types.MsgUnbondResponse, error) {
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

	bond, err := s.k.GetOrInitBond(ctx, msg.NodeId)
	if err != nil {
		return nil, err
	}
	if msg.Units.GT(bond.UnitsBonded) {
		return nil, types.ErrBondInsufficient.Wrapf(
			"requested %s, bonded %s", msg.Units, bond.UnitsBonded)
	}
	bond.UnitsBonded = bond.UnitsBonded.Sub(msg.Units)
	if err := s.k.SetBond(ctx, bond); err != nil {
		return nil, err
	}

	coin := sdk.NewCoin(types.DenomLPUnit, math.NewIntFromBigInt(msg.Units.BigInt()))
	if err := s.k.bankKeeper.SendCoinsFromModuleToAccount(
		ctx, types.BondedAccountName, signer, sdk.NewCoins(coin),
	); err != nil {
		return nil, err
	}

	sdk.UnwrapSDKContext(ctx).EventManager().EmitEvent(
		sdk.NewEvent("lp_unbond",
			sdk.NewAttribute("node_id", msg.NodeId),
			sdk.NewAttribute("units", msg.Units.String()),
			sdk.NewAttribute("total_bonded", bond.UnitsBonded.String()),
		),
	)
	return &types.MsgUnbondResponse{}, nil
}
