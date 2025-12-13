package ebifrost

import (
	"errors"
	"fmt"
	"net"
	"slices"
	"sync"

	"cosmossdk.io/log"
	"github.com/btcq-org/qbtc/x/qbtc/types"
	cmttypes "github.com/cometbft/cometbft/types"
	"github.com/cosmos/cosmos-sdk/codec"
	sdk "github.com/cosmos/cosmos-sdk/types"
	"google.golang.org/grpc"
)

const (
	// ebifrostSignerAcc is the dummy address to submit injected transactions.
	// generated: bech32.ConvertAndEncode(prefix, crypto.AddressHash([]byte("ebifrost_signer")))
	// nolint:unused
	ebifrostSignerAcc = "qbtc102aqxl4u8h9q4lcsruq56kkmeey0v699phhvuv"
	// number of most recent blocks to keep in the cache
	// nolint:unused
	cachedBlocks = 10
)

var _ LocalhostBifrostServer = (*EnshrinedBifrost)(nil)

// EnshrinedBifrost is an embedded btcq service that is used to communicate with bifrost
// for observed transactions and processing quorum attestations.
type EnshrinedBifrost struct {
	s      *grpc.Server
	logger log.Logger
	cdc    codec.Codec
	// started state
	startedMu sync.Mutex
	started   bool

	// subscribers
	// nolint:unused
	subscribersMu sync.Mutex

	subscribers map[string][]chan *EventNotification

	stopCh chan struct{}
	cfg    EBifrostConfig

	// caches
	btcBlockCache *InjectCache[*types.MsgBtcBlock]
}

// NewEnshrinedBifrost creates a new EnshrinedBifrost server.
func NewEnshrinedBifrost(cfg EBifrostConfig, cdc codec.Codec, logger log.Logger) *EnshrinedBifrost {
	s := grpc.NewServer(
		grpc.MaxRecvMsgSize(10*1024*1024), // 10 MB
		grpc.MaxSendMsgSize(10*1024*1024),
	)

	eb := &EnshrinedBifrost{
		s:             s,
		logger:        logger,
		cdc:           cdc,
		cfg:           cfg,
		stopCh:        make(chan struct{}),
		subscribers:   make(map[string][]chan *EventNotification),
		btcBlockCache: NewInjectCache[*types.MsgBtcBlock](),
	}
	RegisterLocalhostBifrostServer(s, eb)
	return eb
}

// Start starts the EnshrinedBifrost server and pruner service if cache ttl is enabled.
func (eb *EnshrinedBifrost) Start() error {
	// if the server is not initialized, return nil
	if eb == nil {
		return nil
	}
	eb.startedMu.Lock()
	defer eb.startedMu.Unlock()
	if eb.started {
		return ErrAlreadyStarted
	}

	lis, err := net.Listen("tcp", eb.cfg.Address)
	if err != nil {
		return err
	}
	eb.started = true
	go func() {
		if err := eb.s.Serve(lis); err != nil && !errors.Is(err, grpc.ErrServerStopped) {
			eb.logger.Error("Enshrined bifrost gRPC server exited", "error", err)
			panic(fmt.Errorf("failed to start enshrined bifrost grpc server: %w", err))
		}
	}()
	// Start the prune timer if TTL is enabled
	if eb.cfg.CacheItemTTL > 0 {
		eb.startPruneTimer()
	}
	return nil
}

func (eb *EnshrinedBifrost) Stop() {
	if eb == nil {
		return
	}
	eb.startedMu.Lock()
	defer eb.startedMu.Unlock()
	if !eb.started {
		return
	}
	eb.started = false

	close(eb.stopCh)
	eb.s.Stop()
}

func (eb *EnshrinedBifrost) MarshalTx(msg sdk.Msg) ([]byte, error) {
	itx := NewInjectTx(eb.cdc, []sdk.Msg{msg})
	return itx.Tx.Marshal()
}

func GetLatestBtcBlockHeight(items []*types.MsgBtcBlock) uint64 {
	if len(items) == 0 {
		return 0
	}

	heights := make([]uint64, len(items))
	for i, item := range items {
		heights[i] = item.Height
	}

	return slices.Max(heights)
}

// ProposalInjectTxs is intended to be called by the current proposing validator during PrepareProposal
// and will return a list of in-quorum transactions to be included in the next block along with the total byte length of the transactions.
func (eb *EnshrinedBifrost) ProposalInjectTxs(ctx sdk.Context, maxTxBytes int64, startBlockHeight uint64) ([][]byte, int64) {
	if eb == nil {
		return nil, 0
	}

	var injectTxs [][]byte
	var txBzLen int64
	ctx.Logger().Info("start btc block height", "height", startBlockHeight)
	// for each btc block cached in EBifrost cache , we only removed it when QBTC already process pass the block height
	// We do not remove it when it is include in the proposal , because the MsgReportBlock handler will ignore the block if it is not the next block height
	// This is to prevent the block being dropped if the proposal is not committed
	for _, item := range eb.btcBlockCache.Get() {
		if item.Height <= startBlockHeight {
			eb.MarkBlockAsProcessed(ctx, item)
		}
	}

	// process btcq blocks
	blocks := eb.btcBlockCache.ProcessForProposal(
		func(b *types.MsgBtcBlock, idx int) bool {
			if startBlockHeight == 0 {
				startBlockHeight = b.Height
				return true
			}
			ctx.Logger().Info("checking btc block for inclusion", "blockHeight", b.Height, "expectedHeight", startBlockHeight+uint64(idx+1), "idx", idx)
			return b.Height == startBlockHeight+uint64(idx+1)
		},
		func(b *types.MsgBtcBlock) (sdk.Msg, error) {
			// construct a new message with the signer set to the ebifrost signer
			block := &types.MsgBtcBlock{
				Height:       b.Height,
				Hash:         b.Hash,
				BlockContent: b.BlockContent,
				Attestations: b.Attestations,
				Signer:       ebifrostSignerAcc,
			}
			return block, nil
		},
		eb.MarshalTx,
		func(block *types.MsgBtcBlock, logger log.Logger) {
			logger.Info("Processed btcq block", "height", block.Height, "hash", block.Hash)
		},
		func(blocks []*types.MsgBtcBlock) {
			slices.SortFunc(blocks, func(a, b *types.MsgBtcBlock) int {
				if a.Height < b.Height {
					return -1
				}
				if a.Height > b.Height {
					return 1
				}
				return 0
			})
		},
		eb.logger,
	)

	for _, bz := range blocks {
		addLen := cmttypes.ComputeProtoSizeForTxs([]cmttypes.Tx{bz})
		if txBzLen+addLen > maxTxBytes {
			continue
		}
		txBzLen += addLen
		injectTxs = append(injectTxs, bz)
	}

	return injectTxs, txBzLen
}
