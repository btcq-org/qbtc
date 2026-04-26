package keeper

import (
	"context"

	sdk "github.com/cosmos/cosmos-sdk/types"

	"github.com/btcq-org/qbtc/x/lp/types"
)

// Bond locks `units` of the caller's free LP units behind their node. Bond
// providers (split co-funders) are not supported in v1; the signer must equal
// node_id.
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

	free, err := s.k.FreeUnits(ctx, msg.NodeId)
	if err != nil {
		return nil, err
	}
	if msg.Units.GT(free) {
		return nil, types.ErrBondInsufficient.Wrapf(
			"requested %s, free %s", msg.Units, free)
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

// Unbond moves units from bonded back to free. v1 has no churn-state gating
// (params.bond_locked_during_churn is read but the validator-set churn logic
// itself is not implemented here); operators can unbond freely. Slashing
// will tighten this in a follow-up.
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

	sdk.UnwrapSDKContext(ctx).EventManager().EmitEvent(
		sdk.NewEvent("lp_unbond",
			sdk.NewAttribute("node_id", msg.NodeId),
			sdk.NewAttribute("units", msg.Units.String()),
			sdk.NewAttribute("total_bonded", bond.UnitsBonded.String()),
		),
	)
	return &types.MsgUnbondResponse{}, nil
}
