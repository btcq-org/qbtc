package ebifrost

import (
	"context"
	"fmt"
	"sync"
	"testing"

	"cosmossdk.io/log"
	storetypes "cosmossdk.io/store/types"
	"github.com/btcq-org/qbtc/x/qbtc/types"
	"github.com/cosmos/cosmos-sdk/testutil"
	"github.com/stretchr/testify/require"
)

func TestInjectCache_RemoveWhere(t *testing.T) {
	cache := NewInjectCache[int]()
	cache.Add(1)
	cache.Add(2)
	cache.Add(3)

	removed := cache.RemoveWhere(func(v int) bool { return v == 2 })
	require.True(t, removed)
	require.Equal(t, []int{1, 3}, cache.Get())

	removed = cache.RemoveWhere(func(v int) bool { return v == 9 })
	require.False(t, removed)
	require.Equal(t, []int{1, 3}, cache.Get())
}

func TestMarkBlockAsProcessed_ConcurrentAccess(t *testing.T) {
	storeKey := storetypes.NewKVStoreKey(types.StoreKey)
	sdkCtx := testutil.DefaultContextWithDB(t, storeKey, storetypes.NewTransientStoreKey("transient_test")).Ctx.WithBlockHeight(100)

	eb := &EnshrinedBifrost{
		logger:        log.NewNopLogger(),
		subscribers:   make(map[string][]chan *EventNotification),
		btcBlockCache: NewInjectCache[*types.MsgBtcBlock](),
	}

	buildBlock := func(key, att int) *types.MsgBtcBlock {
		return &types.MsgBtcBlock{
			Height: uint64(key),
			Hash:   fmt.Sprintf("hash-%d", key),
			Attestations: []*types.Attestation{
				{
					Address:   fmt.Sprintf("validator-%d", att),
					Signature: []byte{byte(att % 255)},
				},
			},
		}
	}

	const (
		numWriters    = 4
		numProcessors = 4
		iterations    = 1500
		keySpace      = 64
	)

	var wg sync.WaitGroup
	start := make(chan struct{})

	for w := 0; w < numWriters; w++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			<-start
			for i := 0; i < iterations; i++ {
				key := (workerID*iterations + i) % keySpace
				_, err := eb.SendBTCBlock(context.Background(), buildBlock(key, workerID*iterations+i))
				require.NoError(t, err)
			}
		}(w)
	}

	for p := 0; p < numProcessors; p++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			<-start
			for i := 0; i < iterations; i++ {
				key := (workerID*iterations + i) % keySpace
				eb.MarkBlockAsProcessed(sdkCtx, buildBlock(key, 0))
			}
		}(p)
	}

	close(start)
	wg.Wait()

	_ = eb.btcBlockCache.Get()
}
