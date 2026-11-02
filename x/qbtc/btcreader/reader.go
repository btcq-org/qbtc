package btcreader

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

// Reader is the Bitcoin reader built into the validator node. A
// goroutine reads the blocks the chain needs next from a Bitcoin node and
// caches them; the ABCI handlers only read the cache and never call Bitcoin.
type Reader struct {
	logger log.Logger
	cdc    codec.Codec
	cfg    Config
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

// NewReader creates the reader. It connects to Bitcoin when started.
func NewReader(cfg Config, cdc codec.Codec, logger log.Logger) *Reader {
	return newReader(cfg, cdc, logger, nil)
}

// NewReaderWithRPC creates the reader on a given Bitcoin RPC client,
// for tests that drive it with Poll.
func NewReaderWithRPC(cfg Config, cdc codec.Codec, logger log.Logger, rpc BitcoinRPC) *Reader {
	return newReader(cfg, cdc, logger, rpc)
}

func newReader(cfg Config, cdc codec.Codec, logger log.Logger, rpc BitcoinRPC) *Reader {
	return &Reader{
		logger: logger.With("module", "btcreader"),
		cdc:    cdc,
		cfg:    cfg,
		rpc:    rpc,
		stopCh: make(chan struct{}),
	}
}

// Start starts the reader goroutine if the reader is enabled. lastProcessed
// tells it which Bitcoin height the chain has processed.
func (rd *Reader) Start(lastProcessed LastProcessedFunc) error {
	if rd == nil || !rd.cfg.Enable {
		return nil
	}
	rd.startedMu.Lock()
	defer rd.startedMu.Unlock()
	if rd.started {
		return ErrAlreadyStarted
	}
	if rd.rpc == nil {
		client, err := bitcoin.NewBtcClient(bitcoin.Config{
			Host:     rd.cfg.BitcoinHost,
			Port:     rd.cfg.BitcoinPort,
			RPCUser:  rd.cfg.BitcoinRPCUser,
			Password: rd.cfg.BitcoinRPCPassword,
			Timeout:  rd.cfg.RPCTimeout,
		}, nil)
		if err != nil {
			return fmt.Errorf("failed to create bitcoin client: %w", err)
		}
		rd.rpc = client
	}
	rd.started = true
	rd.wg.Add(1)
	go rd.run(lastProcessed)
	return nil
}

// Stop stops the reader and waits for its goroutine.
func (rd *Reader) Stop() {
	if rd == nil {
		return
	}
	rd.startedMu.Lock()
	defer rd.startedMu.Unlock()
	if !rd.started {
		return
	}
	rd.started = false

	close(rd.stopCh)
	// closing the client also interrupts a request in flight
	if err := rd.rpc.Close(); err != nil {
		rd.logger.Error("failed to close bitcoin client", "error", err)
	}
	rd.wg.Wait()
}

func (rd *Reader) MarshalTx(msg sdk.Msg) ([]byte, error) {
	itx := NewInjectTx(rd.cdc, []sdk.Msg{msg})
	return itx.Tx.Marshal()
}

// CachedBlocks returns up to max cached blocks at consecutive heights starting
// at from. It stops at the first height that is not cached.
func (rd *Reader) CachedBlocks(from uint64, max int) []CachedBlock {
	if rd == nil {
		return nil
	}
	rd.cacheMu.RLock()
	defer rd.cacheMu.RUnlock()
	var blocks []CachedBlock
	for _, b := range rd.cache {
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
func (rd *Reader) CachedBlock(height uint64) (CachedBlock, bool) {
	if rd == nil {
		return CachedBlock{}, false
	}
	rd.cacheMu.RLock()
	defer rd.cacheMu.RUnlock()
	for _, b := range rd.cache {
		if b.Height == height {
			return b, true
		}
	}
	return CachedBlock{}, false
}

func (rd *Reader) run(lastProcessed LastProcessedFunc) {
	defer rd.wg.Done()
	ticker := time.NewTicker(rd.cfg.PollInterval)
	defer ticker.Stop()
	for {
		last, err := lastProcessed()
		switch {
		case errors.Is(err, ErrNoBtcAnchor):
			// nothing to read until the chain has a Bitcoin anchor
		case err != nil:
			rd.logger.Error("btc reader error", "error", err)
		default:
			if err := rd.Poll(last); err != nil {
				rd.logger.Error("btc reader error", "error", err)
			}
		}
		select {
		case <-rd.stopCh:
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
func (rd *Reader) Poll(last uint64) error {
	rd.pruneProcessed(last)
	if err := rd.dropReorged(); err != nil {
		return err
	}
	tip, err := rd.rpc.GetBlockCount()
	if err != nil {
		return fmt.Errorf("get block count: %w", err)
	}
	for height := last + 1; height <= last+uint64(rd.cfg.MaxCachedBlocks); height++ {
		if _, ok := rd.CachedBlock(height); ok {
			continue
		}
		// the block itself counts as one confirmation
		if tip < 0 || uint64(tip)+1 < height+rd.cfg.ConfirmationDepth {
			break
		}
		block, err := rd.fetchBlock(height)
		if err != nil {
			return fmt.Errorf("fetch block %d: %w", height, err)
		}
		rd.cacheMu.Lock()
		rd.cache = append(rd.cache, block)
		rd.cacheMu.Unlock()
		rd.logger.Info("btc block cached", "height", block.Height, "hash", block.Hash)
	}
	return nil
}

// pruneProcessed drops the cached blocks the chain has processed.
func (rd *Reader) pruneProcessed(last uint64) {
	rd.cacheMu.Lock()
	defer rd.cacheMu.Unlock()
	rd.cache = slices.DeleteFunc(rd.cache, func(b CachedBlock) bool { return b.Height <= last })
}

// dropReorged compares the cached blocks with the node's best chain and drops
// the first block whose hash changed and all blocks above it, which no longer
// build on the cached chain.
func (rd *Reader) dropReorged() error {
	rd.cacheMu.RLock()
	cached := slices.Clone(rd.cache)
	rd.cacheMu.RUnlock()
	for _, b := range cached {
		hash, err := rd.rpc.GetBlockHash(int64(b.Height))
		if err != nil {
			return fmt.Errorf("get hash of block %d: %w", b.Height, err)
		}
		if hash == b.Hash {
			continue
		}
		rd.logger.Info("btc reorg, dropping cached blocks", "from", b.Height, "cached_hash", b.Hash, "hash", hash)
		rd.cacheMu.Lock()
		rd.cache = slices.DeleteFunc(rd.cache, func(c CachedBlock) bool { return c.Height >= b.Height })
		rd.cacheMu.Unlock()
		return nil
	}
	return nil
}

// fetchBlock reads the block at height from the node and checks that it is
// well-formed: it hashes to the hash the node gave for the height, and the
// merkle root of its transactions matches its header. The chain applies the
// full set of Bitcoin checks again when it processes the block.
func (rd *Reader) fetchBlock(height uint64) (CachedBlock, error) {
	hash, err := rd.rpc.GetBlockHash(int64(height))
	if err != nil {
		return CachedBlock{}, fmt.Errorf("get block hash: %w", err)
	}
	block, err := rd.rpc.GetBlock(hash)
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
