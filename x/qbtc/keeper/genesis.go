package keeper

import (
	"context"
	"fmt"

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
	for _, utxo := range genState.Utxos {
		err := k.Utxoes.Set(ctx, utxo.GetKey(), *utxo)
		if err != nil {
			return fmt.Errorf("failed to set UTXO %s: %w", utxo.Txid, err)
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
	if err := k.Utxoes.Walk(ctx, nil, func(key string, value types.UTXO) (stop bool, err error) {
		genesis.Utxos = append(genesis.Utxos, &value)
		return false, nil
	}); err != nil {
		return nil, fmt.Errorf("failed to export UTXOs: %w", err)
	}

	return genesis, nil
}
