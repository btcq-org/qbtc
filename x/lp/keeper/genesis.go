package keeper

import (
	"context"

	"cosmossdk.io/math"
	sdk "github.com/cosmos/cosmos-sdk/types"

	securedtypes "github.com/btcq-org/qbtc/x/secured/types"

	"github.com/btcq-org/qbtc/x/lp/types"
)

// InitGenesis writes the lp module's genesis state. If the supplied pool is
// empty (PoolUnits == 0), the keeper seeds the pool with 1 sat sbtc / 1 sat
// qbtc / 1 unit so the pool has a price from block 1. Genesis seed sbtc must
// already exist on-chain (it's typically minted by x/secured InitGenesis,
// which runs first) and the seed qbtc must already be present in the lp
// module account (genesis allocator transfers it in).
func (k *Keeper) InitGenesis(ctx context.Context, gs *types.GenesisState) error {
	if gs.Pool != nil {
		if err := k.Pool.Set(ctx, *gs.Pool); err != nil {
			return err
		}
	} else {
		if err := k.Pool.Set(ctx, types.Pool{
			BalanceSbtc:        math.ZeroUint(),
			BalanceQbtc:        math.ZeroUint(),
			PoolUnits:          math.ZeroUint(),
			PendingInboundSbtc: math.ZeroUint(),
			PendingInboundQbtc: math.ZeroUint(),
			Status:             types.PoolStatus_POOL_STATUS_STAGED,
		}); err != nil {
			return err
		}
	}

	for _, lp := range gs.LiquidityProviders {
		if err := k.SetLP(ctx, lp); err != nil {
			return err
		}
	}
	for _, b := range gs.Bonds {
		if err := k.SetBond(ctx, b); err != nil {
			return err
		}
	}
	for _, pa := range gs.PendingAdds {
		if err := k.PendingAdds.Set(ctx, pa.Id, pa); err != nil {
			return err
		}
		if pa.Status == types.PendingStatus_PENDING_STATUS_OPEN {
			if err := k.PendingAddByNode.Set(ctx, pa.NodeId, pa.Id); err != nil {
				return err
			}
		}
	}
	if err := k.PendingAddSeq.Set(ctx, gs.PendingAddSeq); err != nil {
		return err
	}
	for _, p := range gs.Params {
		if err := k.ConstOverrides.Set(ctx, p.Key, p.Value); err != nil {
			return err
		}
	}

	// Seed pool to 1 sat / 1 sat / 1 unit if still empty so swaps have a
	// non-degenerate price from block 1. The 1-sat sbtc + 1-sat qbtc seed is
	// minted directly by the lp module (one-time at genesis only — handlers
	// never call MintCoins). The seed is irretrievable in practice: the LP
	// math never permits a withdraw that would drain the pool below zero
	// units, so the genesis 1-unit anchor stays put forever.
	pool, err := k.Pool.Get(ctx)
	if err != nil {
		return err
	}
	if pool.PoolUnits.IsZero() {
		one := math.OneUint()
		oneInt := math.OneInt()

		if err := k.bankKeeper.MintCoins(ctx, types.ModuleName, sdk.NewCoins(
			sdk.NewCoin(securedtypes.DenomSecuredBTC, oneInt),
			sdk.NewCoin(types.DenomQbtc, oneInt),
		)); err != nil {
			return err
		}

		pool.BalanceSbtc = pool.BalanceSbtc.Add(one)
		pool.BalanceQbtc = pool.BalanceQbtc.Add(one)
		pool.PoolUnits = pool.PoolUnits.Add(one)
		if pool.Status == types.PoolStatus_POOL_STATUS_UNSPECIFIED ||
			pool.Status == types.PoolStatus_POOL_STATUS_STAGED {
			pool.Status = types.PoolStatus_POOL_STATUS_AVAILABLE
		}
		if err := k.Pool.Set(ctx, pool); err != nil {
			return err
		}
	}
	return nil
}

func (k *Keeper) ExportGenesis(ctx context.Context) (*types.GenesisState, error) {
	gs := &types.GenesisState{}

	p, err := k.Pool.Get(ctx)
	if err != nil {
		return nil, err
	}
	gs.Pool = &p

	if err := k.LPs.Walk(ctx, nil, func(_ string, lp types.LiquidityProvider) (bool, error) {
		gs.LiquidityProviders = append(gs.LiquidityProviders, lp)
		return false, nil
	}); err != nil {
		return nil, err
	}
	if err := k.Bonds.Walk(ctx, nil, func(_ string, b types.Bond) (bool, error) {
		gs.Bonds = append(gs.Bonds, b)
		return false, nil
	}); err != nil {
		return nil, err
	}
	if err := k.PendingAdds.Walk(ctx, nil, func(_ uint64, pa types.PendingAdd) (bool, error) {
		gs.PendingAdds = append(gs.PendingAdds, pa)
		return false, nil
	}); err != nil {
		return nil, err
	}
	seq, err := k.PendingAddSeq.Peek(ctx)
	if err == nil {
		gs.PendingAddSeq = seq
	}
	if err := k.ConstOverrides.Walk(ctx, nil, func(key string, value int64) (bool, error) {
		gs.Params = append(gs.Params, types.Param{Key: key, Value: value})
		return false, nil
	}); err != nil {
		return nil, err
	}
	return gs, nil
}
