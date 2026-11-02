package app

import (
	"fmt"

	"cosmossdk.io/log"
	"cosmossdk.io/store/iavl"
	storetypes "cosmossdk.io/store/types"
)

// repairIncompleteCommit rolls the stores back to the last committed version
// when an IAVL store holds nodes of the next one.
//
// IAVL writes a large commit to disk in several batches, with the version's
// root node last. A node killed in the middle of it (a hard kill, the OOM
// killer, a power loss) keeps the nodes written so far without the root. IAVL
// then counts the version as existing, so when CometBFT replays the block at
// start, committing it fails with "version does not exist" and the node
// cannot start again without `qbtcd rollback`. Dropping the partial version
// lets the replay commit the block again.
func repairIncompleteCommit(cms storetypes.CommitMultiStore, keys []storetypes.StoreKey, logger log.Logger) error {
	committed := cms.LastCommitID().Version
	if committed == 0 {
		return nil
	}
	for _, key := range keys {
		st, ok := cms.GetCommitKVStore(key).(*iavl.Store)
		if !ok || !st.VersionExists(committed+1) {
			continue
		}
		logger.Error("store holds an incomplete commit, dropping it", "store", key.Name(), "version", committed+1, "committed", committed)
		if err := cms.RollbackToVersion(committed); err != nil {
			return fmt.Errorf("drop the incomplete commit %d of store %s: %w", committed+1, key.Name(), err)
		}
		return nil
	}
	return nil
}
