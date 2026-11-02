package btcreader_test

import (
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"cosmossdk.io/log"
	"github.com/btcsuite/btcd/blockchain"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
	"github.com/stretchr/testify/require"

	"github.com/btcq-org/qbtc/x/qbtc/btcreader"
	"github.com/btcq-org/qbtc/x/qbtc/types"
)

// fakeBitcoin is an in-memory Bitcoin node.
type fakeBitcoin struct {
	mu     sync.Mutex
	blocks map[int64]*wire.MsgBlock // best chain by height
	tip    int64
	calls  int
	err    error // returned by every call while set
	closed bool
}

func newFakeBitcoin() *fakeBitcoin {
	return &fakeBitcoin{blocks: make(map[int64]*wire.MsgBlock)}
}

// mine sets the best chain from height from to height to. Blocks mined with
// different salts differ, which is how a test makes a reorg.
func (b *fakeBitcoin) mine(from, to int64, salt byte) {
	b.mu.Lock()
	defer b.mu.Unlock()
	var prev chainhash.Hash
	if parent, ok := b.blocks[from-1]; ok {
		prev = parent.BlockHash()
	}
	for h := from; h <= to; h++ {
		coinbase := wire.NewMsgTx(2)
		coinbase.AddTxIn(wire.NewTxIn(wire.NewOutPoint(&chainhash.Hash{}, wire.MaxPrevOutIndex), []byte{byte(h), byte(h >> 8), salt}, nil))
		coinbase.AddTxOut(wire.NewTxOut(50, []byte{0x51}))
		block := wire.NewMsgBlock(&wire.BlockHeader{
			Version:    4,
			PrevBlock:  prev,
			MerkleRoot: blockchain.CalcMerkleRoot([]*btcutil.Tx{btcutil.NewTx(coinbase)}, false),
			Timestamp:  time.Unix(1_700_000_000+h, 0),
		})
		if err := block.AddTransaction(coinbase); err != nil {
			panic(err)
		}
		b.blocks[h] = block
		prev = block.BlockHash()
	}
	for h := range b.blocks {
		if h > to {
			delete(b.blocks, h)
		}
	}
	b.tip = to
}

func (b *fakeBitcoin) hashAt(h int64) string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.blocks[h].BlockHash().String()
}

func (b *fakeBitcoin) GetBlockCount() (int64, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.calls++
	return b.tip, b.err
}

func (b *fakeBitcoin) GetBlockHash(height int64) (string, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.calls++
	if b.err != nil {
		return "", b.err
	}
	block, ok := b.blocks[height]
	if !ok {
		return "", fmt.Errorf("block %d out of range", height)
	}
	return block.BlockHash().String(), nil
}

func (b *fakeBitcoin) GetBlock(hash string) (*wire.MsgBlock, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.calls++
	if b.err != nil {
		return nil, b.err
	}
	for _, block := range b.blocks {
		if block.BlockHash().String() == hash {
			return block, nil
		}
	}
	return nil, fmt.Errorf("block %s not found", hash)
}

func (b *fakeBitcoin) Close() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.closed = true
	return nil
}

func (b *fakeBitcoin) callCount() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.calls
}

func readerConfig(depth uint64, maxCached int) btcreader.Config {
	cfg := btcreader.DefaultConfig()
	cfg.Enable = true
	cfg.ConfirmationDepth = depth
	cfg.MaxCachedBlocks = maxCached
	cfg.PollInterval = 10 * time.Millisecond
	return cfg
}

func newReader(cfg btcreader.Config, rpc btcreader.BitcoinRPC) *btcreader.Reader {
	return btcreader.NewReaderWithRPC(cfg, nil, log.NewNopLogger(), rpc)
}

func cachedHeights(rd *btcreader.Reader, from uint64) []uint64 {
	var heights []uint64
	for _, b := range rd.CachedBlocks(from, 1000) {
		heights = append(heights, b.Height)
	}
	return heights
}

func TestReaderCachesBlocksWithEnoughConfirmations(t *testing.T) {
	node := newFakeBitcoin()
	node.mine(1, 10, 0)
	rd := newReader(readerConfig(6, 16), node)

	// the chain has processed 3; a block with tip-height+1 >= 6 confirmations qualifies
	require.NoError(t, rd.Poll(3))
	require.Equal(t, []uint64{4, 5}, cachedHeights(rd, 4))

	// more blocks are mined
	node.mine(11, 12, 0)
	require.NoError(t, rd.Poll(3))
	require.Equal(t, []uint64{4, 5, 6, 7}, cachedHeights(rd, 4))

	// a depth of 1 takes the tip itself
	rd = newReader(readerConfig(1, 16), node)
	require.NoError(t, rd.Poll(9))
	require.Equal(t, []uint64{10, 11, 12}, cachedHeights(rd, 10))
}

func TestReaderCachedBlockContent(t *testing.T) {
	node := newFakeBitcoin()
	node.mine(1, 8, 0)
	rd := newReader(readerConfig(1, 16), node)
	require.NoError(t, rd.Poll(4))

	block, ok := rd.CachedBlock(5)
	require.True(t, ok)
	require.Equal(t, uint64(5), block.Height)
	require.Equal(t, node.hashAt(5), block.Hash)
	signBytes, commit, err := types.DecodeBtcBlockContent(block.Content)
	require.NoError(t, err)
	require.Equal(t, types.BtcCommitHash(signBytes), block.CommitHash)
	header, txs, err := types.ParseBtcBlockCommit(commit)
	require.NoError(t, err)
	require.Equal(t, node.hashAt(5), header.BlockHash().String())
	require.Len(t, txs, 1)

	_, ok = rd.CachedBlock(4)
	require.False(t, ok, "the chain has processed 4")
	_, ok = rd.CachedBlock(100)
	require.False(t, ok)
}

func TestReaderLimitsCachedBlocks(t *testing.T) {
	node := newFakeBitcoin()
	node.mine(1, 100, 0)
	rd := newReader(readerConfig(1, 3), node)
	require.NoError(t, rd.Poll(10))
	require.Equal(t, []uint64{11, 12, 13}, cachedHeights(rd, 11))
}

func TestReaderPrunesProcessedBlocks(t *testing.T) {
	node := newFakeBitcoin()
	node.mine(1, 20, 0)
	rd := newReader(readerConfig(1, 3), node)
	require.NoError(t, rd.Poll(10))
	require.Equal(t, []uint64{11, 12, 13}, cachedHeights(rd, 11))

	// the chain processed 11 and 12; the reader keeps 13 and refills
	require.NoError(t, rd.Poll(12))
	require.Equal(t, []uint64{13, 14, 15}, cachedHeights(rd, 13))
	_, ok := rd.CachedBlock(12)
	require.False(t, ok)

	// a chain that jumped ahead drops everything below
	require.NoError(t, rd.Poll(16))
	require.Equal(t, []uint64{17, 18, 19}, cachedHeights(rd, 17))
	require.Empty(t, rd.CachedBlocks(13, 10), "nothing is cached from 13 any more")
}

func TestReaderReorg(t *testing.T) {
	node := newFakeBitcoin()
	node.mine(1, 12, 0)
	rd := newReader(readerConfig(1, 16), node)
	require.NoError(t, rd.Poll(4))
	old7, _ := rd.CachedBlock(7)
	old6, _ := rd.CachedBlock(6)

	// the best chain forks at 7 and grows
	node.mine(7, 14, 1)
	require.NoError(t, rd.Poll(4))

	new7, ok := rd.CachedBlock(7)
	require.True(t, ok)
	require.NotEqual(t, old7.Hash, new7.Hash, "the reorged block is replaced")
	require.Equal(t, node.hashAt(7), new7.Hash)
	kept6, _ := rd.CachedBlock(6)
	require.Equal(t, old6, kept6, "blocks below the fork are kept")
	require.Equal(t, []uint64{5, 6, 7, 8, 9, 10, 11, 12, 13, 14}, cachedHeights(rd, 5))
	for h := uint64(7); h <= 14; h++ {
		b, _ := rd.CachedBlock(h)
		require.Equal(t, node.hashAt(int64(h)), b.Hash)
	}
}

func TestReaderReorgBelowDepthShrinksCache(t *testing.T) {
	node := newFakeBitcoin()
	node.mine(1, 12, 0)
	rd := newReader(readerConfig(6, 16), node)
	require.NoError(t, rd.Poll(4))
	require.Equal(t, []uint64{5, 6, 7}, cachedHeights(rd, 5))

	// the chain forks at 6 and is shorter, so 6 and 7 no longer have 6 confirmations
	node.mine(6, 9, 1)
	require.NoError(t, rd.Poll(4))
	require.Equal(t, []uint64{5}, cachedHeights(rd, 5))
}

func TestReaderRejectsBadBlocks(t *testing.T) {
	node := newFakeBitcoin()
	node.mine(1, 10, 0)
	// a block whose merkle root is not that of its transactions
	node.blocks[5].Header.MerkleRoot = chainhash.Hash{9}
	rd := newReader(readerConfig(1, 16), node)

	err := rd.Poll(3)
	require.ErrorContains(t, err, "fetch block 5")
	require.Equal(t, []uint64{4}, cachedHeights(rd, 4), "blocks before the bad one are kept")
	_, ok := rd.CachedBlock(5)
	require.False(t, ok)
}

func TestReaderKeepsCacheOnErrorsAndRetries(t *testing.T) {
	node := newFakeBitcoin()
	node.mine(1, 10, 0)
	rd := newReader(readerConfig(1, 4), node)
	require.NoError(t, rd.Poll(3))
	require.Equal(t, []uint64{4, 5, 6, 7}, cachedHeights(rd, 4))

	node.err = errors.New("connection refused")
	require.ErrorContains(t, rd.Poll(3), "connection refused")
	require.Equal(t, []uint64{4, 5, 6, 7}, cachedHeights(rd, 4), "the cache survives an unreachable node")

	node.err = nil
	require.NoError(t, rd.Poll(5))
	require.Equal(t, []uint64{6, 7, 8, 9}, cachedHeights(rd, 6))
}

func TestCachedBlocksAreConsecutive(t *testing.T) {
	node := newFakeBitcoin()
	node.mine(1, 20, 0)
	rd := newReader(readerConfig(1, 10), node)
	require.NoError(t, rd.Poll(0))

	require.Equal(t, []uint64{1, 2, 3}, cachedHeights(rd, 1)[:3])
	require.Len(t, rd.CachedBlocks(1, 4), 4, "limited by max")
	require.Len(t, rd.CachedBlocks(8, 10), 3, "limited by the cache")
	require.Empty(t, rd.CachedBlocks(11, 10), "does not start at an uncached height")
	var nilReader *btcreader.Reader
	require.Empty(t, nilReader.CachedBlocks(1, 10))
}

func TestReaderStartStop(t *testing.T) {
	node := newFakeBitcoin()
	node.mine(1, 10, 0)
	cfg := readerConfig(1, 16)
	rd := newReader(cfg, node)

	last := uint64(2)
	var mu sync.Mutex
	require.NoError(t, rd.Start(func() (uint64, error) {
		mu.Lock()
		defer mu.Unlock()
		return last, nil
	}))
	require.ErrorIs(t, rd.Start(nil), btcreader.ErrAlreadyStarted)
	require.Eventually(t, func() bool { return len(rd.CachedBlocks(3, 100)) == 8 }, 5*time.Second, 5*time.Millisecond)

	mu.Lock()
	last = 5
	mu.Unlock()
	require.Eventually(t, func() bool {
		_, ok := rd.CachedBlock(5)
		return !ok
	}, 5*time.Second, 5*time.Millisecond)

	rd.Stop()
	require.True(t, node.closed, "stopping closes the Bitcoin client")
	rd.Stop() // a second stop is a no-op
}

func TestReaderWaitsForAnchor(t *testing.T) {
	node := newFakeBitcoin()
	node.mine(1, 10, 0)
	rd := newReader(readerConfig(1, 16), node)
	require.NoError(t, rd.Start(func() (uint64, error) { return 0, btcreader.ErrNoBtcAnchor }))
	time.Sleep(100 * time.Millisecond)
	rd.Stop()
	require.Zero(t, node.callCount(), "no Bitcoin call before the chain has an anchor")
	require.Empty(t, rd.CachedBlocks(1, 10))
}

func TestReaderDisabled(t *testing.T) {
	node := newFakeBitcoin()
	cfg := readerConfig(1, 16)
	cfg.Enable = false
	rd := newReader(cfg, node)
	require.NoError(t, rd.Start(func() (uint64, error) { return 0, nil }))
	rd.Stop()
	require.Zero(t, node.callCount())
	require.False(t, node.closed)
}
