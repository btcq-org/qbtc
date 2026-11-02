package app

import (
	"encoding/binary"
	"testing"

	"cosmossdk.io/log"
	"cosmossdk.io/store/iavl"
	"cosmossdk.io/store/metrics"
	"cosmossdk.io/store/rootmulti"
	storetypes "cosmossdk.io/store/types"
	dbm "github.com/cosmos/cosmos-db"
	"github.com/stretchr/testify/require"
)

func TestRepairIncompleteCommit(t *testing.T) {
	db := dbm.NewMemDB()
	key := storetypes.NewKVStoreKey("test")
	open := func() storetypes.CommitMultiStore {
		cms := rootmulti.NewStore(db, log.NewNopLogger(), metrics.NewNoOpMetrics())
		cms.MountStoreWithDB(key, storetypes.StoreTypeIAVL, nil)
		require.NoError(t, cms.LoadLatestVersion())
		return cms
	}
	cms := open()
	cms.GetKVStore(key).Set([]byte("k"), []byte("v"))
	require.EqualValues(t, 1, cms.Commit().Version)

	// a node of version 2 without the version's root, as a commit interrupted
	// between two batch writes leaves behind: IAVL node keys are
	// 's' + version (8 bytes) + nonce (4 bytes), nonce 1 is the root
	orphan := []byte("s/k:test/s")
	orphan = binary.BigEndian.AppendUint64(orphan, 2)
	orphan = binary.BigEndian.AppendUint32(orphan, 2)
	require.NoError(t, db.Set(orphan, []byte{0}))

	cms = open()
	require.EqualValues(t, 1, cms.LastCommitID().Version)
	require.True(t, cms.GetCommitKVStore(key).(*iavl.Store).VersionExists(2))
	// without the repair, the next commit cannot save version 2
	require.Panics(t, func() {
		broken := open()
		broken.GetKVStore(key).Set([]byte("k2"), []byte("v2"))
		broken.Commit()
	})

	require.NoError(t, repairIncompleteCommit(cms, []storetypes.StoreKey{key}, log.NewNopLogger()))
	require.False(t, cms.GetCommitKVStore(key).(*iavl.Store).VersionExists(2))
	require.Equal(t, []byte("v"), cms.GetKVStore(key).Get([]byte("k")))
	cms.GetKVStore(key).Set([]byte("k2"), []byte("v2"))
	require.EqualValues(t, 2, cms.Commit().Version)

	// a healthy store is left alone
	healthy := open()
	require.NoError(t, repairIncompleteCommit(healthy, []storetypes.StoreKey{key}, log.NewNopLogger()))
	require.EqualValues(t, 2, healthy.LastCommitID().Version)
	require.Equal(t, []byte("v2"), healthy.GetKVStore(key).Get([]byte("k2")))
}
