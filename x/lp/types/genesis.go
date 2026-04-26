package types

import (
	"cosmossdk.io/math"
)

// DefaultGenesis returns the default lp module genesis state. Callers (the
// chain's genesis writer) override Pool, Vault references, and any non-default
// params. The pool starts Staged with zero balances; InitGenesis seeds 1 sat
// of each side and 1 LP unit so the pool transitions to Available with a
// price.
func DefaultGenesis() *GenesisState {
	params := make([]Param, 0, len(DefaultParams()))
	for k, v := range DefaultParams() {
		params = append(params, Param{Key: k, Value: v})
	}
	return &GenesisState{
		Pool: &Pool{
			BalanceSbtc:        math.ZeroUint(),
			BalanceQbtc:        math.ZeroUint(),
			PoolUnits:          math.ZeroUint(),
			PendingInboundSbtc: math.ZeroUint(),
			PendingInboundQbtc: math.ZeroUint(),
			Status:             PoolStatus_POOL_STATUS_STAGED,
		},
		PendingAddSeq: 0,
		Params:        params,
	}
}

// Validate sanity-checks the genesis state.
func (gs GenesisState) Validate() error {
	if gs.Pool == nil {
		return ErrPoolNotAvailable.Wrap("genesis pool is nil")
	}
	for _, p := range gs.Params {
		if p.Key == "" {
			return ErrUnknownParam.Wrap("empty key")
		}
		if !IsKnownParam(p.Key) {
			return ErrUnknownParam.Wrapf("%q", p.Key)
		}
	}
	return nil
}
