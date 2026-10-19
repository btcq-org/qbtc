package ebifrost

import (
	"context"
	"fmt"
	"sync"
	"testing"

	"cosmossdk.io/log"
	storetypes "cosmossdk.io/store/types"
	"github.com/btcq-org/qbtc/x/qbtc/types"
	"github.com/cosmos/cosmos-sdk/codec"
	codectypes "github.com/cosmos/cosmos-sdk/codec/types"
	"github.com/cosmos/cosmos-sdk/testutil"
	sdk "github.com/cosmos/cosmos-sdk/types"
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
	errCh := make(chan error, numWriters*iterations)

	for w := 0; w < numWriters; w++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			<-start
			for i := 0; i < iterations; i++ {
				key := (workerID*iterations + i) % keySpace
				_, err := eb.SendBTCBlock(context.Background(), buildBlock(key, workerID*iterations+i))
				errCh <- err
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
	close(errCh)

	for err := range errCh {
		require.NoError(t, err)
	}

	_ = eb.btcBlockCache.Get()
}

// A block too big for the remaining space must end the injected run, not be
// skipped, or the proposal has a gap that ProcessProposal rejects.
func TestProposalInjectTxs_StopsAtBlockThatDoesNotFit(t *testing.T) {
	registry := codectypes.NewInterfaceRegistry()
	types.RegisterInterfaces(registry)
	cdc := codec.NewProtoCodec(registry)
	storeKey := storetypes.NewKVStoreKey(types.StoreKey)
	ctx := testutil.DefaultContextWithDB(t, storeKey, storetypes.NewTransientStoreKey("transient_test")).Ctx

	block := func(height uint64, contentSize int) *types.MsgBtcBlock {
		return &types.MsgBtcBlock{
			Height:       height,
			Hash:         fmt.Sprintf("hash-%d", height),
			BlockContent: make([]byte, contentSize),
			Attestations: []*types.Attestation{{Address: "validator", Signature: []byte{1}}},
		}
	}
	const maxTxBytes = 2_000

	cases := []struct {
		name       string
		blocks     []*types.MsgBtcBlock
		wantHeight []uint64
	}{
		{"first block too big", []*types.MsgBtcBlock{block(101, 5_000), block(102, 100)}, nil},
		{"middle block too big", []*types.MsgBtcBlock{block(101, 100), block(102, 5_000), block(103, 100)}, []uint64{101}},
		{"all fit", []*types.MsgBtcBlock{block(101, 100), block(102, 100)}, []uint64{101, 102}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			eb := &EnshrinedBifrost{
				logger:        log.NewNopLogger(),
				cdc:           cdc,
				subscribers:   make(map[string][]chan *EventNotification),
				btcBlockCache: NewInjectCache[*types.MsgBtcBlock](),
			}
			for _, b := range tc.blocks {
				eb.btcBlockCache.Add(b)
			}

			txs, _ := eb.ProposalInjectTxs(ctx, maxTxBytes, 100)

			decode := TxDecoder(cdc, func([]byte) (sdk.Tx, error) { return nil, fmt.Errorf("not an inject tx") })
			var heights []uint64
			for _, bz := range txs {
				tx, err := decode(bz)
				require.NoError(t, err)
				heights = append(heights, tx.GetMsgs()[0].(*types.MsgBtcBlock).Height)
			}
			require.Equal(t, tc.wantHeight, heights)
		})
	}
}
