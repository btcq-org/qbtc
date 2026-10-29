package abci

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"cosmossdk.io/log"
	storetypes "cosmossdk.io/store/types"
	"github.com/btcsuite/btcd/blockchain"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
	abci "github.com/cometbft/cometbft/abci/types"
	cryptoenc "github.com/cometbft/cometbft/crypto/encoding"
	"github.com/cometbft/cometbft/crypto/mldsa"
	cmtprotocrypto "github.com/cometbft/cometbft/proto/tendermint/crypto"
	cmttypes "github.com/cometbft/cometbft/types"
	"github.com/cosmos/cosmos-sdk/codec"
	addresscodec "github.com/cosmos/cosmos-sdk/codec/address"
	"github.com/cosmos/cosmos-sdk/runtime"
	"github.com/cosmos/cosmos-sdk/testutil"
	sdk "github.com/cosmos/cosmos-sdk/types"
	moduletestutil "github.com/cosmos/cosmos-sdk/types/module/testutil"
	govtypes "github.com/cosmos/cosmos-sdk/x/gov/types"
	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/encoding/protowire"
	protov2 "google.golang.org/protobuf/proto"

	"github.com/btcq-org/qbtc/common"
	"github.com/btcq-org/qbtc/x/qbtc/btcreader"
	"github.com/btcq-org/qbtc/x/qbtc/keeper"
	module "github.com/btcq-org/qbtc/x/qbtc/module"
	qbtctestutil "github.com/btcq-org/qbtc/x/qbtc/testutil"
	"github.com/btcq-org/qbtc/x/qbtc/types"
)

const (
	testChainID      = "qbtc-test"
	testHeight       = 50
	testEnableHeight = 1
	lastProcessed    = 100
)

// plainTx is a regular (not injected) transaction.
type plainTx struct{ msgs []sdk.Msg }

func (t plainTx) GetMsgs() []sdk.Msg { return t.msgs }

func (t plainTx) GetMsgsV2() ([]protov2.Message, error) { return nil, nil }

// fakeBitcoin is a Bitcoin node with a chain of blocks that the reader reads.
type fakeBitcoin struct {
	blocks map[int64]*wire.MsgBlock
}

func newFakeBitcoin(to int64) *fakeBitcoin {
	b := &fakeBitcoin{blocks: make(map[int64]*wire.MsgBlock)}
	var prev chainhash.Hash
	for h := int64(1); h <= to; h++ {
		coinbase := wire.NewMsgTx(2)
		coinbase.AddTxIn(wire.NewTxIn(wire.NewOutPoint(&chainhash.Hash{}, wire.MaxPrevOutIndex), []byte{byte(h), byte(h >> 8)}, nil))
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
	return b
}

func (b *fakeBitcoin) GetBlockCount() (int64, error) { return int64(len(b.blocks)), nil }

func (b *fakeBitcoin) GetBlockHash(height int64) (string, error) {
	block, ok := b.blocks[height]
	if !ok {
		return "", fmt.Errorf("block %d out of range", height)
	}
	return block.BlockHash().String(), nil
}

func (b *fakeBitcoin) GetBlock(hash string) (*wire.MsgBlock, error) {
	for _, block := range b.blocks {
		if block.BlockHash().String() == hash {
			return block, nil
		}
	}
	return nil, fmt.Errorf("block %s not found", hash)
}

func (b *fakeBitcoin) Close() error { return nil }

type abciFixture struct {
	t       *testing.T
	ctx     sdk.Context
	keeper  *keeper.Keeper
	reader  *btcreader.Reader
	handler *ProposalHandler
	decode  func([]byte) (sdk.Tx, error)
	cdc     codec.Codec
	txs     []sdk.Tx // the transactions the decoder hands out for one-byte transactions
	keys    []mldsa.PrivKey
	powers  []int64
}

// newFixture builds a handler for a chain that has processed Bitcoin blocks up
// to lastProcessed, whose reader cached the next cachedBlocks blocks, and with
// validators of the given voting powers.
func newFixture(t *testing.T, cachedBlocks int, powers ...int64) *abciFixture {
	t.Helper()
	sdk.GetConfig().SetBech32PrefixForAccount(common.AccountAddressPrefix, common.AccountAddressPrefix+sdk.PrefixPublic)
	encCfg := moduletestutil.MakeTestEncodingConfig(module.AppModule{})
	storeKey := storetypes.NewKVStoreKey(types.StoreKey)
	ctx := testutil.DefaultContextWithDB(t, storeKey, storetypes.NewTransientStoreKey("transient_test")).Ctx

	ctrl := gomock.NewController(t)
	staking := qbtctestutil.NewMockStakingKeeper(ctrl)
	pubKeys := make(map[string]cmtprotocrypto.PublicKey)
	var keys []mldsa.PrivKey
	for range powers {
		key := mldsa.GenPrivKey()
		pub, err := cryptoenc.PubKeyToProto(key.PubKey())
		require.NoError(t, err)
		pubKeys[string(key.PubKey().Address())] = pub
		keys = append(keys, key)
	}
	staking.EXPECT().GetPubKeyByConsAddr(gomock.Any(), gomock.Any()).AnyTimes().DoAndReturn(
		func(_ context.Context, addr sdk.ConsAddress) (cmtprotocrypto.PublicKey, error) {
			key, ok := pubKeys[string(addr)]
			if !ok {
				return cmtprotocrypto.PublicKey{}, fmt.Errorf("validator %s not found", addr)
			}
			return key, nil
		})
	k := keeper.NewKeeper(
		runtime.NewKVStoreService(storeKey),
		encCfg.Codec,
		addresscodec.NewBech32Codec(common.AccountAddressPrefix),
		staking,
		qbtctestutil.NewMockBankKeeper(ctrl),
		qbtctestutil.NewMockAuthKeeper(ctrl),
		govtypes.ModuleName,
	)
	require.NoError(t, k.LastProcessedBlock.Set(ctx, lastProcessed))

	// the reader fetches the blocks after lastProcessed from a node whose tip is
	// cachedBlocks above, with one confirmation needed
	cfg := btcreader.DefaultConfig()
	cfg.Enable = true
	cfg.ConfirmationDepth = 1
	cfg.MaxCachedBlocks = 32
	eb := btcreader.NewReaderWithRPC(cfg, encCfg.Codec, log.NewNopLogger(), newFakeBitcoin(int64(lastProcessed+cachedBlocks)))
	require.NoError(t, eb.Poll(lastProcessed))

	f := &abciFixture{t: t, ctx: ctx, keeper: k, reader: eb, cdc: encCfg.Codec, keys: keys, powers: powers}
	f.decode = btcreader.TxDecoder(encCfg.Codec, nil)
	f.handler = NewProposalHandler(k, eb, func(bz []byte) (sdk.Tx, error) {
		if len(bz) == 1 && int(bz[0]) < len(f.txs) {
			return f.txs[bz[0]], nil
		}
		return f.decode(bz)
	}, func(_ sdk.Context, _ *abci.RequestPrepareProposal) (*abci.ResponsePrepareProposal, error) {
		return &abci.ResponsePrepareProposal{}, nil
	}, func(_ sdk.Context, _ *abci.RequestProcessProposal) (*abci.ResponseProcessProposal, error) {
		return &abci.ResponseProcessProposal{Status: abci.ResponseProcessProposal_ACCEPT}, nil
	})
	return f
}

// voteFor is the vote extension of a validator that attests the cached blocks
// at the given heights.
func (f *abciFixture) voteFor(heights ...uint64) []byte {
	f.t.Helper()
	var ext types.BtcBlockVoteExtension
	for _, h := range heights {
		block, ok := f.reader.CachedBlock(h)
		require.True(f.t, ok, "block %d is not cached", h)
		ext.Votes = append(ext.Votes, &types.BtcBlockVote{Height: h, Hash: block.Hash, CommitHash: block.CommitHash[:]})
	}
	bz, err := ext.Marshal()
	require.NoError(f.t, err)
	return bz
}

// commit builds the extended commit of the previous height, in which
// validator i's vote extension is exts[i].
func (f *abciFixture) commit(exts ...[]byte) abci.ExtendedCommitInfo {
	votes := make([]qbtctestutil.TestVote, len(f.keys))
	for i, key := range f.keys {
		votes[i] = qbtctestutil.TestVote{Key: key, Power: f.powers[i]}
		if i < len(exts) {
			votes[i].Extension = exts[i]
		}
	}
	return qbtctestutil.NewExtendedCommit(testChainID, testHeight, 0, votes)
}

func (f *abciFixture) voteHash(height uint64) string {
	block, ok := f.reader.CachedBlock(height)
	require.True(f.t, ok)
	return block.Hash
}

// ctxWith returns the context of block testHeight whose last commit is ec.
func (f *abciFixture) ctxWith(ec abci.ExtendedCommitInfo) sdk.Context {
	return qbtctestutil.ContextWithLastCommit(f.ctx, testChainID, testHeight, testEnableHeight, ec)
}

// prepare runs PrepareProposal with ec as the local last commit and returns the
// message of its inject transaction, if any.
func (f *abciFixture) prepare(ec abci.ExtendedCommitInfo, maxTxBytes int64) (*types.MsgBtcBlock, [][]byte) {
	f.t.Helper()
	resp, err := f.handler.PrepareProposal(f.ctxWith(ec), &abci.RequestPrepareProposal{
		MaxTxBytes:      maxTxBytes,
		Height:          testHeight,
		LocalLastCommit: ec,
	})
	require.NoError(f.t, err)
	var msg *types.MsgBtcBlock
	for _, bz := range resp.Txs {
		tx, err := f.decode(bz)
		require.NoError(f.t, err)
		for _, m := range tx.GetMsgs() {
			require.Nil(f.t, msg, "more than one MsgBtcBlock")
			msg = m.(*types.MsgBtcBlock)
		}
	}
	return msg, resp.Txs
}

func heightsOf(msg *types.MsgBtcBlock) []uint64 {
	var heights []uint64
	for _, b := range msg.Blocks {
		heights = append(heights, b.Height)
	}
	return heights
}

func TestPrepareProposalInjectsVotedBlocks(t *testing.T) {
	f := newFixture(t, 6, 40, 30, 30)
	a := f.voteFor(101, 102, 103, 104)

	t.Run("all validators attest", func(t *testing.T) {
		ec := f.commit(a, a, a)
		msg, txs := f.prepare(ec, 10<<20)
		require.NotNil(t, msg)
		require.Len(t, txs, 1, "one inject tx")
		require.Equal(t, []uint64{101, 102, 103, 104}, heightsOf(msg))
		require.Equal(t, types.BtcBlockSignerAddress, msg.Signer)
		require.NotEmpty(t, msg.ExtendedCommitInfo)
		for _, b := range msg.Blocks {
			cached, _ := f.reader.CachedBlock(b.Height)
			require.Equal(t, cached.Hash, b.Hash)
			require.Equal(t, cached.Content, b.BlockContent)
		}
		// the proposal passes the check every validator makes
		require.NoError(t, f.keeper.ValidateBtcBlockVotes(f.ctxWith(ec), msg))
	})

	t.Run("more than 2/3 is enough", func(t *testing.T) {
		// 40+30 = 70 attest
		msg, _ := f.prepare(f.commit(a, a, nil), 10<<20)
		require.NotNil(t, msg)
		require.Equal(t, []uint64{101, 102, 103, 104}, heightsOf(msg))
	})

	t.Run("stops at the first height without a supermajority", func(t *testing.T) {
		// the third validator attests only 101 and 102
		short := f.voteFor(101, 102)
		msg, _ := f.prepare(f.commit(a, a, short), 10<<20)
		require.NotNil(t, msg)
		require.Equal(t, []uint64{101, 102, 103, 104}, heightsOf(msg), "103 has 70 of 100")

		// the second one too: 103 has 40 of 100
		msg, _ = f.prepare(f.commit(a, short, short), 10<<20)
		require.NotNil(t, msg)
		require.Equal(t, []uint64{101, 102}, heightsOf(msg))
	})

	t.Run("exactly 2/3 is not enough", func(t *testing.T) {
		g := newFixture(t, 3, 20, 20, 20)
		ext := g.voteFor(101)
		msg, txs := g.prepare(g.commit(ext, ext, nil), 10<<20)
		require.Nil(t, msg)
		require.Empty(t, txs)
	})

	t.Run("a gap stops the run", func(t *testing.T) {
		// 102 is attested, 101 is not
		msg, txs := f.prepare(f.commit(f.voteFor(102), f.voteFor(102), f.voteFor(102)), 10<<20)
		require.Nil(t, msg)
		require.Empty(t, txs)
	})

	t.Run("no attestations", func(t *testing.T) {
		msg, txs := f.prepare(f.commit(), 10<<20)
		require.Nil(t, msg)
		require.Empty(t, txs)
	})

	t.Run("split votes", func(t *testing.T) {
		g := newFixture(t, 3, 40, 30, 30)
		other := &types.BtcBlockVoteExtension{Votes: []*types.BtcBlockVote{{Height: 101, Hash: strings.Repeat("a", 64), CommitHash: make([]byte, 32)}}}
		otherBz, err := other.Marshal()
		require.NoError(t, err)
		msg, _ := g.prepare(g.commit(g.voteFor(101), otherBz, otherBz), 10<<20)
		require.Nil(t, msg, "the 60 for the other block do not make a supermajority, nor do the 40")
	})

	t.Run("only blocks in the local cache", func(t *testing.T) {
		// the validators attest 101-104; a node that cached fewer blocks includes fewer
		g := newFixture(t, 2, 40, 30, 30)
		msg, _ := g.prepare(g.commit(a, a, a), 10<<20)
		require.NotNil(t, msg)
		require.Equal(t, []uint64{101, 102}, heightsOf(msg))
	})

	t.Run("a cached block other than the attested one is not included", func(t *testing.T) {
		// the validators attest block 101 with another commit hash than this node's
		wrong := &types.BtcBlockVoteExtension{Votes: []*types.BtcBlockVote{{Height: 101, Hash: f.voteHash(101), CommitHash: make([]byte, 32)}}}
		bz, err := wrong.Marshal()
		require.NoError(t, err)
		msg, _ := f.prepare(f.commit(bz, bz, bz), 10<<20)
		require.Nil(t, msg)
	})

	t.Run("at most 8 blocks", func(t *testing.T) {
		g := newFixture(t, 12, 40, 30, 30)
		var heights []uint64
		for h := uint64(101); h <= 112; h++ {
			heights = append(heights, h)
		}
		ext := g.voteFor(heights...)
		msg, _ := g.prepare(g.commit(ext, ext, ext), 100<<20)
		require.NotNil(t, msg)
		require.Len(t, msg.Blocks, types.MaxBtcBlocksPerMsg)
	})

	t.Run("the attested heights cover the next block's injection too", func(t *testing.T) {
		// extensions are built on the state before the block they vote on: after
		// a block that processed MaxBtcBlocksPerMsg, the next proposer injects
		// the rest of the attested heights from the same extensions
		g := newFixture(t, types.MaxBtcBlockVotes, 40, 30, 30)
		var heights []uint64
		for h := uint64(101); h <= uint64(100+types.MaxBtcBlockVotes); h++ {
			heights = append(heights, h)
		}
		ext := g.voteFor(heights...)
		ec := g.commit(ext, ext, ext)
		msg, _ := g.prepare(ec, 100<<20)
		require.NotNil(t, msg)
		require.Equal(t, heights[:types.MaxBtcBlocksPerMsg], heightsOf(msg))

		require.NoError(t, g.keeper.LastProcessedBlock.Set(g.ctx, heights[types.MaxBtcBlocksPerMsg-1]))
		msg, _ = g.prepare(ec, 100<<20)
		require.NotNil(t, msg)
		require.Equal(t, heights[types.MaxBtcBlocksPerMsg:], heightsOf(msg))
		require.NoError(t, g.keeper.ValidateBtcBlockVotes(g.ctxWith(ec), msg))
	})

	t.Run("the byte limit counts the blocks that fit", func(t *testing.T) {
		size := func(txs [][]byte) int64 {
			var n int64
			for _, tx := range txs {
				n += cmttypes.ComputeProtoSizeForTxs([]cmttypes.Tx{tx})
			}
			return n
		}
		ec := f.commit(a, a, a)
		full, txs := f.prepare(ec, 10<<20)
		require.Len(t, full.Blocks, 4)
		// inject transactions may use half of the limit
		msg, _ := f.prepare(ec, 2*size(txs))
		require.Len(t, msg.Blocks, 4)
		msg, _ = f.prepare(ec, 2*size(txs)-2)
		require.NotNil(t, msg)
		require.Less(t, len(msg.Blocks), 4)

		one := f.voteFor(101)
		oneBlock, oneTxs := f.prepare(f.commit(one, one, one), 10<<20)
		require.Len(t, oneBlock.Blocks, 1)
		msg, _ = f.prepare(f.commit(one, one, one), 2*size(oneTxs))
		require.NotNil(t, msg)
		msg, got := f.prepare(f.commit(one, one, one), 2*size(oneTxs)-2)
		require.Nil(t, msg)
		require.Empty(t, got)
	})

	t.Run("vote extensions not enabled", func(t *testing.T) {
		ec := f.commit(a, a, a)
		ctx := qbtctestutil.ContextWithLastCommit(f.ctx, testChainID, testHeight, 0, ec)
		resp, err := f.handler.PrepareProposal(ctx, &abci.RequestPrepareProposal{MaxTxBytes: 10 << 20, Height: testHeight, LocalLastCommit: ec})
		require.NoError(t, err)
		require.Empty(t, resp.Txs)
	})

	t.Run("a commit without valid signatures injects nothing", func(t *testing.T) {
		ec := f.commit(a, a, a)
		ec.Votes[0].ExtensionSignature = ec.Votes[1].ExtensionSignature
		msg, txs := f.prepare(ec, 10<<20)
		require.Nil(t, msg)
		require.Empty(t, txs)
	})
}

func TestExtendVote(t *testing.T) {
	ext := func(f *abciFixture) types.BtcBlockVoteExtension {
		resp, err := f.handler.ExtendVote(f.ctx, &abci.RequestExtendVote{})
		require.NoError(t, err)
		var e types.BtcBlockVoteExtension
		require.NoError(t, e.Unmarshal(resp.VoteExtension))
		require.NoError(t, e.ValidateFormat())
		require.LessOrEqual(t, len(resp.VoteExtension), types.MaxVoteExtensionSize)
		return e
	}

	t.Run("attests the cached blocks from the next height", func(t *testing.T) {
		f := newFixture(t, 3, 100)
		e := ext(f)
		require.Len(t, e.Votes, 3)
		for i, v := range e.Votes {
			require.Equal(t, uint64(101+i), v.Height)
			cached, _ := f.reader.CachedBlock(v.Height)
			require.Equal(t, cached.Hash, v.Hash)
			require.Equal(t, cached.CommitHash[:], v.CommitHash)
		}
	})

	t.Run("at most 16 blocks", func(t *testing.T) {
		f := newFixture(t, 20, 100)
		require.Len(t, ext(f).Votes, types.MaxBtcBlockVotes)
	})

	t.Run("empty without cached blocks", func(t *testing.T) {
		f := newFixture(t, 0, 100)
		resp, err := f.handler.ExtendVote(f.ctx, &abci.RequestExtendVote{})
		require.NoError(t, err)
		require.Empty(t, resp.VoteExtension)
	})

	t.Run("blocks the chain processed are not attested", func(t *testing.T) {
		f := newFixture(t, 3, 100)
		require.NoError(t, f.keeper.LastProcessedBlock.Set(f.ctx, lastProcessed+2))
		e := ext(f)
		require.Len(t, e.Votes, 1)
		require.Equal(t, uint64(103), e.Votes[0].Height)
	})

	t.Run("without a reader", func(t *testing.T) {
		f := newFixture(t, 3, 100)
		h := NewProposalHandler(f.keeper, nil, nil, nil, nil)
		resp, err := h.ExtendVote(f.ctx, &abci.RequestExtendVote{})
		require.NoError(t, err)
		require.Empty(t, resp.VoteExtension)
	})
}

func TestVerifyVoteExtension(t *testing.T) {
	good := func() *types.BtcBlockVote {
		return &types.BtcBlockVote{Height: 101, Hash: strings.Repeat("ab", 32), CommitHash: make([]byte, 32)}
	}
	marshal := func(votes ...*types.BtcBlockVote) []byte {
		bz, err := (&types.BtcBlockVoteExtension{Votes: votes}).Marshal()
		require.NoError(t, err)
		return bz
	}
	with := func(modify func(v *types.BtcBlockVote)) []byte {
		v := good()
		modify(v)
		return marshal(v)
	}
	many := func(n int) []byte {
		votes := make([]*types.BtcBlockVote, n)
		for i := range votes {
			votes[i] = good()
			votes[i].Height = uint64(101 + i)
		}
		return marshal(votes...)
	}

	// a valid extension followed by an unknown field, which Unmarshal skips:
	// only the size check rejects it
	padded := protowire.AppendTag(marshal(good()), 15, protowire.BytesType)
	padded = protowire.AppendBytes(padded, make([]byte, types.MaxVoteExtensionSize))
	var decoded types.BtcBlockVoteExtension
	require.NoError(t, decoded.Unmarshal(padded))
	require.NoError(t, decoded.ValidateFormat())
	require.Greater(t, len(padded), types.MaxVoteExtensionSize)

	cases := []struct {
		name   string
		ext    []byte
		accept bool
	}{
		{"empty", nil, true},
		{"one block", marshal(good()), true},
		{"the maximum number of blocks", many(types.MaxBtcBlockVotes), true},
		{"too many blocks", many(types.MaxBtcBlockVotes + 1), false},
		{"too large", padded, false},
		{"not a vote extension", []byte{0xff, 0xff, 0xff}, false},
		{"duplicate heights", marshal(good(), good()), false},
		{"short commit hash", with(func(v *types.BtcBlockVote) { v.CommitHash = v.CommitHash[:31] }), false},
		{"long commit hash", with(func(v *types.BtcBlockVote) { v.CommitHash = append(v.CommitHash, 0) }), false},
		{"no commit hash", with(func(v *types.BtcBlockVote) { v.CommitHash = nil }), false},
		{"short hash", with(func(v *types.BtcBlockVote) { v.Hash = v.Hash[:63] }), false},
		{"long hash", with(func(v *types.BtcBlockVote) { v.Hash += "a" }), false},
		{"empty hash", with(func(v *types.BtcBlockVote) { v.Hash = "" }), false},
		{"uppercase hash", with(func(v *types.BtcBlockVote) { v.Hash = strings.ToUpper(v.Hash) }), false},
		{"hash that is not hex", with(func(v *types.BtcBlockVote) { v.Hash = strings.Repeat("xy", 32) }), false},
	}
	// the handler has no keeper and no reader: the check depends on nothing local
	h := NewProposalHandler(nil, nil, nil, nil, nil)
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resp, err := h.VerifyVoteExtension(sdk.Context{}.WithLogger(log.NewNopLogger()), &abci.RequestVerifyVoteExtension{VoteExtension: tc.ext})
			require.NoError(t, err)
			if tc.accept {
				require.Equal(t, abci.ResponseVerifyVoteExtension_ACCEPT, resp.Status)
			} else {
				require.Equal(t, abci.ResponseVerifyVoteExtension_REJECT, resp.Status)
			}
		})
	}
}

// injectedMsg is the message a proposer builds for the cached blocks at heights,
// attested by every validator.
func (f *abciFixture) injectedMsg(heights ...uint64) (*types.MsgBtcBlock, abci.ExtendedCommitInfo) {
	f.t.Helper()
	ext := f.voteFor(heights...)
	exts := make([][]byte, len(f.keys))
	for i := range exts {
		exts[i] = ext
	}
	ec := f.commit(exts...)
	msg, _ := f.prepare(ec, 10<<20)
	require.NotNil(f.t, msg)
	return msg, ec
}

func (f *abciFixture) injectTx(msg *types.MsgBtcBlock) sdk.Tx {
	return btcreader.NewInjectTx(f.cdc, []sdk.Msg{msg})
}

func (f *abciFixture) process(ctx sdk.Context, txs ...sdk.Tx) abci.ResponseProcessProposal_ProposalStatus {
	f.t.Helper()
	f.txs = txs
	req := &abci.RequestProcessProposal{Height: testHeight}
	for i := range txs {
		req.Txs = append(req.Txs, []byte{byte(i)})
	}
	resp, err := f.handler.ProcessProposal(ctx, req)
	require.NoError(f.t, err)
	return resp.Status
}

func TestProcessProposal(t *testing.T) {
	const accept, reject = abci.ResponseProcessProposal_ACCEPT, abci.ResponseProcessProposal_REJECT
	f := newFixture(t, 6, 40, 30, 30)
	valid, ec := f.injectedMsg(101, 102, 103)
	ctx := f.ctxWith(ec)
	clone := func() *types.MsgBtcBlock {
		cp := *valid
		cp.Blocks = make([]*types.BtcBlock, len(valid.Blocks))
		for i, b := range valid.Blocks {
			bc := *b
			cp.Blocks[i] = &bc
		}
		return &cp
	}

	t.Run("valid", func(t *testing.T) {
		require.Equal(t, accept, f.process(ctx, f.injectTx(valid)))
	})

	t.Run("no Bitcoin blocks", func(t *testing.T) {
		require.Equal(t, accept, f.process(ctx))
		require.Equal(t, accept, f.process(ctx, plainTx{msgs: []sdk.Msg{&types.MsgEmpty{}}}))
	})

	t.Run("no evidence", func(t *testing.T) {
		msg := clone()
		msg.ExtendedCommitInfo = nil
		require.Equal(t, reject, f.process(ctx, f.injectTx(msg)))
	})

	t.Run("evidence of another commit", func(t *testing.T) {
		other := newFixture(t, 6, 40, 30, 30)
		msg, _ := other.injectedMsg(101, 102, 103)
		require.Equal(t, reject, f.process(ctx, f.injectTx(msg)))
	})

	t.Run("outside an inject transaction", func(t *testing.T) {
		require.Equal(t, reject, f.process(ctx, plainTx{msgs: []sdk.Msg{valid}}))
	})

	t.Run("two MsgBtcBlock", func(t *testing.T) {
		require.Equal(t, reject, f.process(ctx, f.injectTx(valid), f.injectTx(valid)))
	})

	t.Run("gap in the heights", func(t *testing.T) {
		msg := clone()
		msg.Blocks = []*types.BtcBlock{msg.Blocks[0], msg.Blocks[2]}
		require.Equal(t, reject, f.process(ctx, f.injectTx(msg)))
	})

	t.Run("heights not starting at the next one", func(t *testing.T) {
		msg := clone()
		msg.Blocks = msg.Blocks[1:]
		require.Equal(t, reject, f.process(ctx, f.injectTx(msg)))
	})

	t.Run("repeated height", func(t *testing.T) {
		msg := clone()
		msg.Blocks = []*types.BtcBlock{msg.Blocks[0], msg.Blocks[0]}
		require.Equal(t, reject, f.process(ctx, f.injectTx(msg)))
	})

	t.Run("forged content", func(t *testing.T) {
		msg := clone()
		other, ok := f.reader.CachedBlock(104)
		require.True(t, ok)
		msg.Blocks[0].BlockContent = other.Content
		require.Equal(t, reject, f.process(ctx, f.injectTx(msg)))
	})

	t.Run("other hash", func(t *testing.T) {
		msg := clone()
		msg.Blocks[0].Hash = strings.Repeat("c", 64)
		require.Equal(t, reject, f.process(ctx, f.injectTx(msg)))
	})

	t.Run("other signer", func(t *testing.T) {
		msg := clone()
		msg.Signer = sdk.AccAddress(make([]byte, 20)).String()
		require.Equal(t, reject, f.process(ctx, f.injectTx(msg)))
	})

	t.Run("vote extensions not enabled", func(t *testing.T) {
		disabled := qbtctestutil.ContextWithLastCommit(f.ctx, testChainID, testHeight, 0, ec)
		require.Equal(t, reject, f.process(disabled, f.injectTx(valid)))
		require.Equal(t, accept, f.process(disabled), "no Bitcoin blocks need no vote extensions")
	})

	t.Run("insufficient power", func(t *testing.T) {
		ext := f.voteFor(101, 102, 103)
		weak := f.commit(ext, nil, nil) // 40 of 100
		msg := clone()
		bz, err := weak.Marshal()
		require.NoError(t, err)
		msg.ExtendedCommitInfo = bz
		require.Equal(t, reject, f.process(f.ctxWith(weak), f.injectTx(msg)))
	})
}
