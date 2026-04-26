package keeper

import (
	"context"
	"errors"

	"cosmossdk.io/collections"
	"cosmossdk.io/math"

	"github.com/btcq-org/qbtc/x/lp/types"
)

// GetOrInitBond returns the bond record for a node, creating an empty one if
// missing. Caller must Set after mutation.
func (k *Keeper) GetOrInitBond(ctx context.Context, nodeID string) (types.Bond, error) {
	b, err := k.Bonds.Get(ctx, nodeID)
	if err != nil {
		if errors.Is(err, collections.ErrNotFound) {
			return types.Bond{
				NodeId:      nodeID,
				UnitsBonded: math.ZeroUint(),
				Status:      types.BondStatus_BOND_STATUS_STANDBY,
			}, nil
		}
		return types.Bond{}, err
	}
	return b, nil
}

func (k *Keeper) SetBond(ctx context.Context, b types.Bond) error {
	return k.Bonds.Set(ctx, b.NodeId, b)
}
