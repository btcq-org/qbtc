package keeper

import (
	"context"

	"cosmossdk.io/math"
	sdk "github.com/cosmos/cosmos-sdk/types"

	"github.com/btcq-org/qbtc/x/lp/types"
)

// MustGetPool returns the pool, panicking if absent. The pool is seeded at
// InitGenesis, so any post-genesis context must always have it.
func (k *Keeper) MustGetPool(ctx context.Context) types.Pool {
	p, err := k.Pool.Get(ctx)
	if err != nil {
		panic(err)
	}
	return p
}

func (k *Keeper) SetPool(ctx context.Context, p types.Pool) error {
	p.LastUpdatedHeight = sdk.UnwrapSDKContext(ctx).BlockHeight()
	return k.Pool.Set(ctx, p)
}

// EnsurePoolAvailable returns ErrPoolNotAvailable if the pool isn't open for
// adds and swaps.
func (k *Keeper) EnsurePoolAvailable(ctx context.Context) error {
	p := k.MustGetPool(ctx)
	if p.Status != types.PoolStatus_POOL_STATUS_AVAILABLE {
		return types.ErrPoolNotAvailable.Wrapf("status=%s", p.Status)
	}
	return nil
}

// applyDeposit mutates pool balances and units to reflect a successful add.
func applyDeposit(p *types.Pool, btcAdded, qbtcAdded, unitsIssued math.Uint) {
	p.BalanceSbtc = p.BalanceSbtc.Add(btcAdded)
	p.BalanceQbtc = p.BalanceQbtc.Add(qbtcAdded)
	p.PoolUnits = p.PoolUnits.Add(unitsIssued)
}

// applyWithdraw mutates pool balances and units to reflect a successful
// withdraw.
func applyWithdraw(p *types.Pool, btcOut, qbtcOut, unitsBurned math.Uint) {
	p.BalanceSbtc = p.BalanceSbtc.Sub(btcOut)
	p.BalanceQbtc = p.BalanceQbtc.Sub(qbtcOut)
	p.PoolUnits = p.PoolUnits.Sub(unitsBurned)
}

// applySwapInputBTC: pool grew on BTC side by `in`, shrank on qbtc side by `out`.
func applySwapInputBTC(p *types.Pool, in, out math.Uint) {
	p.BalanceSbtc = p.BalanceSbtc.Add(in)
	p.BalanceQbtc = p.BalanceQbtc.Sub(out)
}

// applySwapInputQBTC: pool grew on qbtc side, shrank on BTC side.
func applySwapInputQBTC(p *types.Pool, in, out math.Uint) {
	p.BalanceQbtc = p.BalanceQbtc.Add(in)
	p.BalanceSbtc = p.BalanceSbtc.Sub(out)
}
