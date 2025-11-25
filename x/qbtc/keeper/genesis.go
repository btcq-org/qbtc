package keeper

import (
	"context"
	"encoding/hex"
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

	// Initialize airdrop entries
	for _, entry := range genState.AirdropEntries {
		// Convert address hash bytes to hex key
		addressHashHex := hex.EncodeToString(entry.AddressHash)
		err := k.AirdropEntries.Set(ctx, addressHashHex, entry.Amount)
		if err != nil {
			return fmt.Errorf("failed to set airdrop entry for %s: %w", addressHashHex, err)
		}
		// If the entry is marked as already claimed, record it
		if entry.Claimed {
			err := k.ClaimedAirdrops.Set(ctx, addressHashHex, true)
			if err != nil {
				return fmt.Errorf("failed to set claimed status for %s: %w", addressHashHex, err)
			}
		}
	}

	// Initialize ZK entropy state if provided
	if genState.ZKEntropyState != nil {
		if err := k.ZKEntropyState.Set(ctx, *genState.ZKEntropyState); err != nil {
			return fmt.Errorf("failed to set ZK entropy state: %w", err)
		}

		// Restore individual submissions
		for _, sub := range genState.ZKEntropyState.Submissions {
			if err := k.ZKEntropySubmissions.Set(ctx, sub.Validator, sub); err != nil {
				return fmt.Errorf("failed to set ZK entropy submission for %s: %w", sub.Validator, err)
			}
		}
	}

	// Initialize ZK setup keys if provided
	if genState.ZKSetupKeys != nil {
		if err := k.ZKSetupKeys.Set(ctx, *genState.ZKSetupKeys); err != nil {
			return fmt.Errorf("failed to set ZK setup keys: %w", err)
		}

		// Initialize the default verifier with the stored verifying key
		if len(genState.ZKSetupKeys.VerifyingKey) > 0 {
			if err := zk.InitDefaultVerifier(genState.ZKSetupKeys.VerifyingKey); err != nil {
				sdkCtx.Logger().Error("failed to initialize ZK verifier from genesis", "error", err)
				// Don't fail genesis - the key can be loaded later
			} else {
				sdkCtx.Logger().Info("ZK verifier initialized from genesis")
			}
		}
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

	// Export airdrop entries
	airdropEntries := make([]types.AirdropEntry, 0)
	if err := k.AirdropEntries.Walk(ctx, nil, func(key string, value uint64) (stop bool, err error) {
		// Check if claimed
		claimed, _ := k.ClaimedAirdrops.Get(ctx, key)

		// Convert hex key back to bytes
		addressHash, err := hex.DecodeString(key)
		if err != nil {
			return false, fmt.Errorf("failed to decode address hash %s: %w", key, err)
		}

		airdropEntries = append(airdropEntries, types.AirdropEntry{
			AddressHash: addressHash,
			Amount:      value,
			Claimed:     claimed,
		})
		return false, nil
	}); err != nil {
		return nil, fmt.Errorf("failed to export airdrop entries: %w", err)
	}
	genesis.AirdropEntries = airdropEntries

	// Export ZK entropy state
	zkEntropyState, err := k.ZKEntropyState.Get(ctx)
	if err == nil {
		genesis.ZKEntropyState = &zkEntropyState
	}

	// Export ZK setup keys
	zkSetupKeys, err := k.ZKSetupKeys.Get(ctx)
	if err == nil {
		genesis.ZKSetupKeys = &zkSetupKeys
	}

	return genesis, nil
}
