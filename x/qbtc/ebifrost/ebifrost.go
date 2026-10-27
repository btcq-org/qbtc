package ebifrost

import (
	"errors"
	"fmt"
	"slices"
	"sync"
	"time"

	"cosmossdk.io/log"
	"github.com/btcsuite/btcd/blockchain"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/wire"
	"github.com/cosmos/cosmos-sdk/codec"
	sdk "github.com/cosmos/cosmos-sdk/types"

	"github.com/btcq-org/qbtc/bitcoin"
	"github.com/btcq-org/qbtc/x/qbtc/types"
)

// BitcoinRPC is the part of the Bitcoin node RPC the reader uses.
type BitcoinRPC interface {
	GetBlockCount() (int64, error)
	GetBlockHash(height int64) (string, error)
	GetBlock(hash string) (*wire.MsgBlock, error)
	Close() error
}

// LastProcessedFunc returns the height of the last Bitcoin block in the latest
// committed chain state, or ErrNoBtcAnchor if the chain has no anchor.
type LastProcessedFunc func() (uint64, error)

// CachedBlock is a Bitcoin block the reader has fetched and checked, ready to
// be attested in a vote extension and proposed.
type CachedBlock struct {
	Height uint64
	Hash   string
	// Content is the gzip-compressed BtcBlockCommit, as carried in MsgBtcBlock.
	Content []byte
	// CommitHash is the SHA-256 of the uncompressed BtcBlockCommit.
	CommitHash [types.BtcCommitHashSize]byte
}

// EnshrinedBifrost is the Bitcoin reader built into the validator node. A
// goroutine reads the blocks the chain needs next from a Bitcoin node and
// caches them; the ABCI handlers only read the cache and never call Bitcoin.
type EnshrinedBifrost struct {
	logger log.Logger
	cdc    codec.Codec
	cfg    EBifrostConfig
	rpc    BitcoinRPC

	// started state
	startedMu sync.Mutex
	started   bool
	stopCh    chan struct{}
	wg        sync.WaitGroup

	// cache of consecutive blocks, ordered by height
	cacheMu sync.RWMutex
	cache   []CachedBlock
}

// NewEnshrinedBifrost creates the reader. It connects to Bitcoin when started.
func NewEnshrinedBifrost(cfg EBifrostConfig, cdc codec.Codec, logger log.Logger) *EnshrinedBifrost {
	return newEnshrinedBifrost(cfg, cdc, logger, nil)
}

// NewEnshrinedBifrostWithRPC creates the reader on a given Bitcoin RPC client,
// for tests that drive it with Poll.
func NewEnshrinedBifrostWithRPC(cfg EBifrostConfig, cdc codec.Codec, logger log.Logger, rpc BitcoinRPC) *EnshrinedBifrost {
	return newEnshrinedBifrost(cfg, cdc, logger, rpc)
}

func newEnshrinedBifrost(cfg EBifrostConfig, cdc codec.Codec, logger log.Logger, rpc BitcoinRPC) *EnshrinedBifrost {
	return &EnshrinedBifrost{
		logger: logger.With("module", "ebifrost"),
		cdc:    cdc,
		cfg:    cfg,
		rpc:    rpc,
		stopCh: make(chan struct{}),
	}
}

// Start starts the reader goroutine if the reader is enabled. lastProcessed
// tells it which Bitcoin height the chain has processed.
func (eb *EnshrinedBifrost) Start(lastProcessed LastProcessedFunc) error {
	if eb == nil || !eb.cfg.Enable {
		return nil
	}
	eb.startedMu.Lock()
	defer eb.startedMu.Unlock()
	if eb.started {
		return ErrAlreadyStarted
	}
	if eb.rpc == nil {
		client, err := bitcoin.NewBtcClient(bitcoin.Config{
			Host:     eb.cfg.BitcoinHost,
			Port:     eb.cfg.BitcoinPort,
			RPCUser:  eb.cfg.BitcoinRPCUser,
			Password: eb.cfg.BitcoinRPCPassword,
			Timeout:  eb.cfg.RPCTimeout,
		}, nil)
		if err != nil {
			return fmt.Errorf("failed to create bitcoin client: %w", err)
		}
		eb.rpc = client
	}
	eb.started = true
	eb.wg.Add(1)
	go eb.run(lastProcessed)
	return nil
}

// Stop stops the reader and waits for its goroutine.
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
	// closing the client also interrupts a request in flight
	if err := eb.rpc.Close(); err != nil {
		eb.logger.Error("failed to close bitcoin client", "error", err)
	}
	eb.wg.Wait()
}

func (eb *EnshrinedBifrost) MarshalTx(msg sdk.Msg) ([]byte, error) {
	itx := NewInjectTx(eb.cdc, []sdk.Msg{msg})
	return itx.Tx.Marshal()
}

// CachedBlocks returns up to max cached blocks at consecutive heights starting
// at from. It stops at the first height that is not cached.
func (eb *EnshrinedBifrost) CachedBlocks(from uint64, max int) []CachedBlock {
	if eb == nil {
		return nil
	}
	eb.cacheMu.RLock()
	defer eb.cacheMu.RUnlock()
	var blocks []CachedBlock
	for _, b := range eb.cache {
		if b.Height < from {
			continue
		}
		if b.Height != from+uint64(len(blocks)) || len(blocks) >= max {
			break
		}
		blocks = append(blocks, b)
	}
	return blocks
}

// CachedBlock returns the cached block at height.
func (eb *EnshrinedBifrost) CachedBlock(height uint64) (CachedBlock, bool) {
	if eb == nil {
		return CachedBlock{}, false
	}
	eb.cacheMu.RLock()
	defer eb.cacheMu.RUnlock()
	for _, b := range eb.cache {
		if b.Height == height {
			return b, true
		}
	}
	return CachedBlock{}, false
}

func (eb *EnshrinedBifrost) run(lastProcessed LastProcessedFunc) {
	defer eb.wg.Done()
	ticker := time.NewTicker(eb.cfg.PollInterval)
	defer ticker.Stop()
	for {
		last, err := lastProcessed()
		switch {
		case errors.Is(err, ErrNoBtcAnchor):
			// nothing to read until the chain has a Bitcoin anchor
		case err != nil:
			eb.logger.Error("btc reader error", "error", err)
		default:
			if err := eb.Poll(last); err != nil {
				eb.logger.Error("btc reader error", "error", err)
			}
		}
		select {
		case <-eb.stopCh:
			return
		case <-ticker.C:
		}
	}
}

// Poll runs one iteration of the reader. It brings the cache up to date with the chain, which has processed Bitcoin
// blocks up to last, and with the Bitcoin node. It drops blocks the chain has
// processed and blocks the node no longer has on its best chain, then fetches
// the next blocks that have enough confirmations. On an error the cache keeps
// what it has and the next poll retries.
func (eb *EnshrinedBifrost) Poll(last uint64) error {
	eb.pruneProcessed(last)
	if err := eb.dropReorged(); err != nil {
		return err
	}
	tip, err := eb.rpc.GetBlockCount()
	if err != nil {
		return fmt.Errorf("get block count: %w", err)
	}
	for height := last + 1; height <= last+uint64(eb.cfg.MaxCachedBlocks); height++ {
		if _, ok := eb.CachedBlock(height); ok {
			continue
		}
		// the block itself counts as one confirmation
		if tip < 0 || uint64(tip)+1 < height+eb.cfg.ConfirmationDepth {
			break
		}
		block, err := eb.fetchBlock(height)
		if err != nil {
			return fmt.Errorf("fetch block %d: %w", height, err)
		}
		eb.cacheMu.Lock()
		eb.cache = append(eb.cache, block)
		eb.cacheMu.Unlock()
		eb.logger.Info("btc block cached", "height", block.Height, "hash", block.Hash)
	}
	return nil
}

// pruneProcessed drops the cached blocks the chain has processed.
func (eb *EnshrinedBifrost) pruneProcessed(last uint64) {
	eb.cacheMu.Lock()
	defer eb.cacheMu.Unlock()
	eb.cache = slices.DeleteFunc(eb.cache, func(b CachedBlock) bool { return b.Height <= last })
}

// dropReorged compares the cached blocks with the node's best chain and drops
// the first block whose hash changed and all blocks above it, which no longer
// build on the cached chain.
func (eb *EnshrinedBifrost) dropReorged() error {
	eb.cacheMu.RLock()
	cached := slices.Clone(eb.cache)
	eb.cacheMu.RUnlock()
	for _, b := range cached {
		hash, err := eb.rpc.GetBlockHash(int64(b.Height))
		if err != nil {
			return fmt.Errorf("get hash of block %d: %w", b.Height, err)
		}
		if hash == b.Hash {
			continue
		}
		eb.logger.Info("btc reorg, dropping cached blocks", "from", b.Height, "cached_hash", b.Hash, "hash", hash)
		eb.cacheMu.Lock()
		eb.cache = slices.DeleteFunc(eb.cache, func(c CachedBlock) bool { return c.Height >= b.Height })
		eb.cacheMu.Unlock()
		return nil
	}
	return nil
}

// fetchBlock reads the block at height from the node and checks that it is
// well-formed: it hashes to the hash the node gave for the height, and the
// merkle root of its transactions matches its header. The chain applies the
// full set of Bitcoin checks again when it processes the block.
func (eb *EnshrinedBifrost) fetchBlock(height uint64) (CachedBlock, error) {
	hash, err := eb.rpc.GetBlockHash(int64(height))
	if err != nil {
		return CachedBlock{}, fmt.Errorf("get block hash: %w", err)
	}
	block, err := eb.rpc.GetBlock(hash)
	if err != nil {
		return CachedBlock{}, fmt.Errorf("get block: %w", err)
	}
	if got := block.BlockHash().String(); got != hash {
		return CachedBlock{}, fmt.Errorf("node returned block %s for %s", got, hash)
	}
	if len(block.Transactions) == 0 {
		return CachedBlock{}, fmt.Errorf("block %s has no transactions", hash)
	}
	utxs := make([]*btcutil.Tx, len(block.Transactions))
	for i, tx := range block.Transactions {
		utxs[i] = btcutil.NewTx(tx)
	}
	if root := blockchain.CalcMerkleRoot(utxs, false); root != block.Header.MerkleRoot {
		return CachedBlock{}, fmt.Errorf("block %s merkle root %s does not match the header %s", hash, root, block.Header.MerkleRoot)
	}
	commit, err := types.NewBtcBlockCommit(block)
	if err != nil {
		return CachedBlock{}, err
	}
	signBytes, content, err := types.EncodeBtcBlockCommit(commit)
	if err != nil {
		return CachedBlock{}, err
	}
	return CachedBlock{
		Height:     height,
		Hash:       hash,
		Content:    content,
		CommitHash: types.BtcCommitHash(signBytes),
	}, nil
}
