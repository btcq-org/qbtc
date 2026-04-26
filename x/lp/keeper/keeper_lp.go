package keeper

import (
	"context"
	"errors"

	"cosmossdk.io/collections"
	"cosmossdk.io/math"

	"github.com/btcq-org/qbtc/x/lp/types"
)

// GetOrInitLP returns the LP record for a node, creating an empty one if it
// doesn't exist. The caller must Set it back after mutation.
func (k *Keeper) GetOrInitLP(ctx context.Context, nodeID string) (types.LiquidityProvider, error) {
	lp, err := k.LPs.Get(ctx, nodeID)
	if err != nil {
		if errors.Is(err, collections.ErrNotFound) {
			return types.LiquidityProvider{
				NodeId: nodeID,
				Units:  math.ZeroUint(),
			}, nil
		}
		return types.LiquidityProvider{}, err
	}
	return lp, nil
}

func (k *Keeper) SetLP(ctx context.Context, lp types.LiquidityProvider) error {
	return k.LPs.Set(ctx, lp.NodeId, lp)
}

// FreeUnits returns the LP's units that aren't currently bonded. Bond is a
// sub-amount of LP.Units, so free = Units - Bond.UnitsBonded.
func (k *Keeper) FreeUnits(ctx context.Context, nodeID string) (math.Uint, error) {
	lp, err := k.LPs.Get(ctx, nodeID)
	if err != nil {
		if errors.Is(err, collections.ErrNotFound) {
			return math.ZeroUint(), nil
		}
		return math.ZeroUint(), err
	}
	bond, err := k.GetOrInitBond(ctx, nodeID)
	if err != nil {
		return math.ZeroUint(), err
	}
	if bond.UnitsBonded.GTE(lp.Units) {
		return math.ZeroUint(), nil
	}
	return lp.Units.Sub(bond.UnitsBonded), nil
}
