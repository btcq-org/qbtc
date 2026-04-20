package keeper

import (
	"context"
	"errors"
	"fmt"

	"cosmossdk.io/collections"
	"github.com/btcq-org/qbtc/x/qbtc/zk"
)

// EnsureZKVerifierInitialized loads the ZK verifying key from chain state and
// initializes the process-local global verifier if it has not been initialized
// yet.
//
// The verifier is an in-memory singleton and its state does not survive a node
// restart, whereas the VK is persisted in chain state. This method rehydrates
// the in-memory verifier from state so that claims continue to work after a
// restart, not only immediately after InitGenesis.
func (k Keeper) EnsureZKVerifierInitialized(ctx context.Context) error {
	if zk.IsVerifierInitialized() {
		return nil
	}

	vkBytes, err := k.ZkVerifyingKey.Get(ctx)
	if err != nil {
		if errors.Is(err, collections.ErrNotFound) {
			return nil
		}
		return fmt.Errorf("failed to load ZK verifying key from state: %w", err)
	}
	if len(vkBytes) == 0 {
		return nil
	}

	if err := zk.InitializeVerifier(vkBytes); err != nil {
		return fmt.Errorf("failed to initialize ZK verifier: %w", err)
	}
	return nil
}
