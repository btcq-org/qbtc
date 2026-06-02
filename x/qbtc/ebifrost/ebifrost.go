package ebifrost

import (
	"fmt"
	"sync"
	"sync/atomic"

	"cosmossdk.io/log"
	"github.com/btcq-org/qbtc/bitcoin"
	"github.com/cosmos/cosmos-sdk/codec"
	sdk "github.com/cosmos/cosmos-sdk/types"
)

// SignerAcc is the fixed signer address placed on injected txs.
// generated: bech32.ConvertAndEncode(prefix, crypto.AddressHash([]byte("ebifrost_signer")))
const SignerAcc = "qbtc102aqxl4u8h9q4lcsruq56kkmeey0v699phhvuv"

// EnshrinedBifrost is the embedded Bitcoin observer. Each validator node runs it
// to fetch Bitcoin blocks directly from its configured RPC endpoint, build
// minimal UTXO deltas, and cache them. ExtendVote attests the cached deltas'
// digests and PrepareProposal injects the supermajority-agreed delta.
type EnshrinedBifrost struct {
	logger log.Logger
	cdc    codec.Codec
	cfg    EBifrostConfig

	startedMu sync.Mutex
	started   bool
	stopCh    chan struct{}
	wg        sync.WaitGroup

	// btcDeltaCache holds observed minimal block deltas keyed by Bitcoin height,
	// filled by the observer goroutine and read by ExtendVote / PrepareProposal.
	deltaMu       sync.RWMutex
	btcDeltaCache map[uint64]cachedDelta

	// btc is the Bitcoin RPC client; nil when observation is not configured.
	btc *bitcoin.BtcClient
	// floor is the chain's last-processed Bitcoin height, published each block by
	// ExtendVote. The observer fetches blocks above it and prunes at or below it.
	floor atomic.Uint64
}

// NewEnshrinedBifrost creates the embedded observer. When the Bitcoin RPC host
// is unset the observer stays idle (the node attests empty vote extensions).
func NewEnshrinedBifrost(cfg EBifrostConfig, cdc codec.Codec, logger log.Logger) *EnshrinedBifrost {
	eb := &EnshrinedBifrost{
		logger:        logger,
		cdc:           cdc,
		cfg:           cfg,
		stopCh:        make(chan struct{}),
		btcDeltaCache: make(map[uint64]cachedDelta),
	}
	if cfg.Enable && cfg.BitcoinHost != "" {
		btc, err := bitcoin.NewBtcClient(bitcoin.Config{
			Host:     cfg.BitcoinHost,
			Port:     cfg.BitcoinPort,
			RPCUser:  cfg.BitcoinRPCUser,
			Password: cfg.BitcoinPassword,
		}, nil)
		if err != nil {
			// The observer is explicitly configured; a broken client is a
			// misconfiguration, not a reason to silently start without
			// contributing vote extensions.
			panic(fmt.Errorf("ebifrost: bitcoin observer configured but client creation failed: %w", err))
		}
		eb.btc = btc
	}
	return eb
}

// Start launches the observer goroutine when observation is configured.
func (eb *EnshrinedBifrost) Start() error {
	if eb == nil || !eb.cfg.Enable || eb.btc == nil {
		return nil
	}
	eb.startedMu.Lock()
	defer eb.startedMu.Unlock()
	if eb.started {
		return ErrAlreadyStarted
	}
	eb.started = true
	eb.wg.Add(1)
	go eb.observe()
	eb.logger.Info("embedded bitcoin observer started",
		"host", eb.cfg.BitcoinHost, "min_confirmations", eb.cfg.MinConfirmations)
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
	eb.wg.Wait()
	if eb.btc != nil {
		_ = eb.btc.Close()
	}
}

// MarshalTx wraps a message in the proposer-injected tx envelope.
func (eb *EnshrinedBifrost) MarshalTx(msg sdk.Msg) ([]byte, error) {
	itx := NewInjectTx(eb.cdc, []sdk.Msg{msg})
	return itx.Tx.Marshal()
}
