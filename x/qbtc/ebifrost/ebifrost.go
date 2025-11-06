package ebifrost

import (
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"cosmossdk.io/log"
	"github.com/cosmos/cosmos-sdk/codec"
	sdk "github.com/cosmos/cosmos-sdk/types"
	"google.golang.org/grpc"
)

const (
	// ebifrostSignerAcc is the dummy address to submit injected transactions.
	// generated: bech32.ConvertAndEncode(prefix, crypto.AddressHash([]byte("ebifrost_signer")))
	// nolint:unused
	ebifrostSignerAcc = "btcq102aqxl4u8h9q4lcsruq56kkmeey0v699s5q0ll"
	// number of most recent blocks to keep in the cache
	cachedBlocks = 10
)

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

}

// NewEnshrinedBifrost creates a new EnshrinedBifrost server.
func NewEnshrinedBifrost(cfg EBifrostConfig, cdc codec.Codec, logger log.Logger) *EnshrinedBifrost {
	s := grpc.NewServer()
	return &EnshrinedBifrost{
		s:           s,
		logger:      logger,
		cdc:         cdc,
		cfg:         cfg,
		stopCh:      make(chan struct{}),
		subscribers: make(map[string][]chan *EventNotification),
	}
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

// nolint:unused
func (eb *EnshrinedBifrost) broadcastEvent(eventType string, payload []byte) {
	event := &EventNotification{
		EventType: eventType,
		Payload:   payload,
		Timestamp: time.Now().Unix(),
	}

	eb.subscribersMu.Lock()
	subscribers := eb.subscribers[eventType]
	eb.subscribersMu.Unlock()

	for _, ch := range subscribers {
		select {
		case ch <- event:
			eb.logger.Debug("Event sent to subscriber", "event", eventType)
			// Event sent successfully
		default:
			eb.logger.Error("Failed to send event to subscriber", "event", eventType)
			// Channel is full or closed, could implement cleanup here
		}
	}
}

func (eb *EnshrinedBifrost) MarshalTx(msg sdk.Msg) ([]byte, error) {
	itx := NewInjectTx(eb.cdc, []sdk.Msg{msg})
	return itx.Tx.Marshal()
}

// ProposalInjectTxs is intended to be called by the current proposing validator during PrepareProposal
// and will return a list of in-quorum transactions to be included in the next block along with the total byte length of the transactions.
func (eb *EnshrinedBifrost) ProposalInjectTxs(ctx sdk.Context, maxTxBytes int64) ([][]byte, int64) {
	if eb == nil {
		return nil, 0
	}

	var injectTxs [][]byte
	var txBzLen int64

	return injectTxs, txBzLen
}
