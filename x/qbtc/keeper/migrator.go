package keeper

import (
	sdk "github.com/cosmos/cosmos-sdk/types"

	v2 "github.com/btcq-org/qbtc/x/qbtc/migrations/v2"
)

// Migrator is the keeper helper that runs in-place store migrations across
// ConsensusVersion bumps.
type Migrator struct {
	keeper *Keeper
}

// NewMigrator returns a Migrator bound to the given keeper.
func NewMigrator(k *Keeper) Migrator {
	return Migrator{keeper: k}
}

// Migrate1to2 backfills the Utxoes ByAddress secondary index introduced in
// ConsensusVersion 2.
func (m Migrator) Migrate1to2(ctx sdk.Context) error {
	return v2.MigrateStore(ctx, m.keeper.Utxoes)
}
