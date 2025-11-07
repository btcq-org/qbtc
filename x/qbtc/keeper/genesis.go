package keeper

import (
	"context"

	"github.com/btcq-org/qbtc/x/qbtc/types"
)

// InitGenesis initializes the module's state from a provided genesis state.
func (k Keeper) InitGenesis(ctx context.Context, genState types.GenesisState) error {
	for _, nodeIP := range genState.NodeIPs {
		err := k.NodeIPs.Set(ctx, nodeIP.Validator, nodeIP.IP)
		if err != nil {
			return err
		}
	}
	return nil
}

// ExportGenesis returns the module's exported genesis.
func (k Keeper) ExportGenesis(ctx context.Context) (*types.GenesisState, error) {
	genesis := types.DefaultGenesis()
	ips := make([]types.GenesisNodeIP, 0)
	err := k.NodeIPs.Walk(ctx, nil, func(key string, value string) (stop bool, err error) {
		ips = append(ips, types.GenesisNodeIP{
			Validator: key,
			IP:        value,
		})
		return false, nil
	})
	if err != nil {
		return nil, err
	}
	genesis.NodeIPs = ips
	return genesis, nil
}
