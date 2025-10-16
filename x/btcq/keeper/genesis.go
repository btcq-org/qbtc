package keeper

import (
	"context"

	"github.com/btcq-org/btcq/x/btcq/types"
)

// InitGenesis initializes the module's state from a provided genesis state.
func (k Keeper) InitGenesis(ctx context.Context, genState types.GenesisState) error {
	return nil
}

// ExportGenesis returns the module's exported genesis.
func (k Keeper) ExportGenesis(ctx context.Context) (*types.GenesisState, error) {

	genesis := types.DefaultGenesis()

	return genesis, nil
}
