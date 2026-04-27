package keeper

import (
	"context"
	"errors"

	"cosmossdk.io/collections"

	"github.com/btcq-org/qbtc/x/lp/types"
)

// GetOrInitLP returns the LP-binding record for a node, creating an empty one
// (with no BTC address yet) if none exists. The record only binds the
// withdraw destination; per-node free-unit balance lives in the bank as
// `lp/btc-qbtc`.
func (k *Keeper) GetOrInitLP(ctx context.Context, nodeID string) (types.LiquidityProvider, error) {
	lp, err := k.LPs.Get(ctx, nodeID)
	if err != nil {
		if errors.Is(err, collections.ErrNotFound) {
			return types.LiquidityProvider{NodeId: nodeID}, nil
		}
		return types.LiquidityProvider{}, err
	}
	return lp, nil
}

func (k *Keeper) SetLP(ctx context.Context, lp types.LiquidityProvider) error {
	return k.LPs.Set(ctx, lp.NodeId, lp)
}
