package keeper

import (
	"context"
	"fmt"

	"github.com/btcq-org/qbtc/x/qbtc/types"
	"github.com/btcq-org/qbtc/x/qbtc/zk"
	sdk "github.com/cosmos/cosmos-sdk/types"
)

// InitGenesis initializes the module's state from a provided genesis state.
func (k Keeper) InitGenesis(ctx context.Context, genState types.GenesisState) error {
	sdkCtx := sdk.UnwrapSDKContext(ctx)

	for _, nodePeerAddress := range genState.PeerAddresses {
		err := k.NodePeerAddresses.Set(ctx, nodePeerAddress.Validator, nodePeerAddress.PeerAddress)
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
	for _, item := range genState.Params {
		err := k.ConstOverrides.Set(ctx, item.Key, item.Value)
		if err != nil {
			return fmt.Errorf("failed to set param %s: %w", item.Key, err)
		}
	}

	// Initialize ZK verifying key from genesis
	if len(genState.ZkVerifyingKey) > 0 {
		// Store the VK in state
		if err := k.ZkVerifyingKey.Set(ctx, genState.ZkVerifyingKey); err != nil {
			return fmt.Errorf("failed to set ZK verifying key: %w", err)
		}

		// Register the global verifier (for BTCSignatureCircuit - TSS compatible)
		if err := zk.RegisterVerifier(genState.ZkVerifyingKey); err != nil {
			sdkCtx.Logger().Error("failed to register ZK verifier from genesis", "error", err)
			return fmt.Errorf("failed to register ZK verifier: %w", err)
		}
		sdkCtx.Logger().Info("ZK PLONK verifier registered from genesis")
	} else {
		sdkCtx.Logger().Warn("no ZK verifying key in genesis - airdrop claims will fail until VK is set")
	}

	return nil
}

// ExportGenesis returns the module's exported genesis.
func (k Keeper) ExportGenesis(ctx context.Context) (*types.GenesisState, error) {
	genesis := types.DefaultGenesis()
	ips := make([]types.GenesisPeerAddress, 0)
	err := k.NodePeerAddresses.Walk(ctx, nil, func(key string, value string) (stop bool, err error) {
		ips = append(ips, types.GenesisPeerAddress{
			Validator:   key,
			PeerAddress: value,
		})
		return false, nil
	})
	if err != nil {
		return nil, err
	}
	genesis.PeerAddresses = ips
	if err := k.Utxoes.Walk(ctx, nil, func(key string, value types.UTXO) (stop bool, err error) {
		genesis.Utxos = append(genesis.Utxos, &value)
		return false, nil
	}); err != nil {
		return nil, fmt.Errorf("failed to export UTXOs: %w", err)
	}

	// export const overrides as params
	params := make([]*types.Param, 0)
	if err := k.ConstOverrides.Walk(ctx, nil, func(key string, value int64) (stop bool, err error) {
		params = append(params, &types.Param{
			Key:   key,
			Value: value,
		})
		return false, nil
	}); err != nil {
		return nil, fmt.Errorf("failed to export params: %w", err)
	}
	genesis.Params = params

	// Export ZK verifying key
	zkVK, err := k.ZkVerifyingKey.Get(ctx)
	if err == nil && len(zkVK) > 0 {
		genesis.ZkVerifyingKey = zkVK
	}

	return genesis, nil
}

