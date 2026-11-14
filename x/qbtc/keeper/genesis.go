package keeper

import (
	"context"
	"errors"
	"fmt"

	"cosmossdk.io/collections"
	"github.com/btcq-org/qbtc/x/qbtc/types"
	sdk "github.com/cosmos/cosmos-sdk/types"
)

// InitGenesis initializes the module's state from a provided genesis state.
func (k Keeper) InitGenesis(ctx context.Context, genState types.GenesisState) error {
	sdkCtx := sdk.UnwrapSDKContext(ctx)

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
	for _, stats := range genState.ReferralStats {
		addr, err := sdk.AccAddressFromBech32(stats.Address)
		if err != nil {
			return fmt.Errorf("invalid referral stats address %s: %w", stats.Address, err)
		}
		if err := k.ReferralStats.Set(ctx, addr, stats); err != nil {
			return fmt.Errorf("failed to set referral stats %s: %w", stats.Address, err)
		}
	}
	for i, hash := range genState.UtxoChunkHashes {
		if err := k.UtxoChunkHashes.Set(ctx, uint64(i), hash); err != nil {
			return fmt.Errorf("failed to set utxo chunk hash %d: %w", i, err)
		}
	}

	// Initialize ZK verifying key from genesis
	if len(genState.ZkVerifyingKey) > 0 {
		// Store the VK in state
		if err := k.ZkVerifyingKey.Set(ctx, genState.ZkVerifyingKey); err != nil {
			return fmt.Errorf("failed to set ZK verifying key: %w", err)
		}

		// Initialize the global verifier (for BTCPubKeyOwnershipCircuit - TSS compatible)
		if err := k.EnsureZKVerifierInitialized(ctx); err != nil {
			sdkCtx.Logger().Error("failed to initialize ZK verifier from genesis", "error", err)
			return fmt.Errorf("failed to initialize ZK verifier: %w", err)
		}
		sdkCtx.Logger().Info("ZK PLONK verifier initialized from genesis")
	} else {
		sdkCtx.Logger().Warn("no ZK verifying key in genesis - airdrop claims will fail until VK is set")
	}

	// set the last processed block height to the initial block height - 1
	if genState.BtcInitialHeight > 0 {
		err := k.LastProcessedBlock.Set(ctx, genState.BtcInitialHeight-1)
		if err != nil {
			return fmt.Errorf("failed to set last processed block height: %w", err)
		}
	}
	// the anchor is the block at BtcInitialHeight - 1; the first reported block must link to it
	if len(genState.BtcAnchorHeader) > 0 {
		if err := k.BtcTipHeader.Set(ctx, genState.BtcAnchorHeader); err != nil {
			return fmt.Errorf("failed to set btc anchor header: %w", err)
		}
		if err := k.BtcPeriodStartTime.Set(ctx, uint64(genState.BtcAnchorPeriodStartTime)); err != nil {
			return fmt.Errorf("failed to set btc anchor period start time: %w", err)
		}
	}
	return nil
}

// ExportGenesis returns the module's exported genesis.
func (k Keeper) ExportGenesis(ctx context.Context) (*types.GenesisState, error) {
	// Once the snapshot is loaded, every UTXO is exported below, so the
	// exported genesis needs no chunks. Before that, part of the snapshot is
	// only in the chunk files.
	next, _, loaded, err := k.NextUtxoChunk(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to read utxo snapshot progress: %w", err)
	}
	if !loaded {
		return nil, fmt.Errorf("cannot export while the genesis UTXO snapshot is loading (chunk %d is next)", next)
	}

	genesis := types.DefaultGenesis()
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

	if err := k.ReferralStats.Walk(ctx, nil, func(_ sdk.AccAddress, stats types.ReferralStats) (stop bool, err error) {
		genesis.ReferralStats = append(genesis.ReferralStats, stats)
		return false, nil
	}); err != nil {
		return nil, fmt.Errorf("failed to export referral stats: %w", err)
	}

	// Export ZK verifying key
	zkVK, err := k.ZkVerifyingKey.Get(ctx)
	if err == nil && len(zkVK) > 0 {
		genesis.ZkVerifyingKey = zkVK
	}

	// Export the Bitcoin tip as the anchor, so the imported chain continues
	// from the next block.
	lastProcessed, err := k.GetLastProcessedBlock(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to export last processed block: %w", err)
	}
	if lastProcessed > 0 {
		genesis.BtcInitialHeight = lastProcessed + 1
	}
	tip, err := k.BtcTipHeader.Get(ctx)
	switch {
	case err == nil:
		periodStart, err := k.BtcPeriodStartTime.Get(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to export btc period start time: %w", err)
		}
		genesis.BtcAnchorHeader = tip
		genesis.BtcAnchorPeriodStartTime = uint32(periodStart)
	case !errors.Is(err, collections.ErrNotFound):
		return nil, fmt.Errorf("failed to export btc tip header: %w", err)
	}

	return genesis, nil
}
