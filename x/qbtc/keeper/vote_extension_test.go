package keeper_test

import (
	"crypto/sha256"
	"strings"
	"testing"

	"github.com/btcsuite/btcd/wire"
	abci "github.com/cometbft/cometbft/abci/types"
	cryptoenc "github.com/cometbft/cometbft/crypto/encoding"
	"github.com/cometbft/cometbft/crypto/mldsa"
	cmtproto "github.com/cometbft/cometbft/proto/tendermint/types"
	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/encoding/protowire"

	"github.com/btcq-org/qbtc/x/qbtc/keeper"
	qbtctestutil "github.com/btcq-org/qbtc/x/qbtc/testutil"
	"github.com/btcq-org/qbtc/x/qbtc/types"
)

func hexHash(c byte) string { return strings.Repeat(string(rune(c)), 64) }

func commitHashOf(c byte) []byte {
	sum := sha256.Sum256([]byte{c})
	return sum[:]
}

// vote builds the vote extension attesting (height, hash c, commit hash of c).
func voteExt(t *testing.T, votes ...*types.BtcBlockVote) []byte {
	t.Helper()
	bz, err := (&types.BtcBlockVoteExtension{Votes: votes}).Marshal()
	require.NoError(t, err)
	return bz
}

func btcVote(height uint64, c byte) *types.BtcBlockVote {
	return &types.BtcBlockVote{Height: height, Hash: hexHash(c), CommitHash: commitHashOf(c)}
}

// unsignedCommit is an extended commit that is only tallied, not validated.
func unsignedCommit(votes ...abci.ExtendedVoteInfo) abci.ExtendedCommitInfo {
	return abci.ExtendedCommitInfo{Votes: votes}
}

func commitVote(power int64, ext []byte) abci.ExtendedVoteInfo {
	return abci.ExtendedVoteInfo{
		Validator:     abci.Validator{Power: power},
		VoteExtension: ext,
		BlockIdFlag:   cmtproto.BlockIDFlagCommit,
	}
}

func voteKey(c byte) keeper.BtcVoteKey {
	key := keeper.BtcVoteKey{Hash: hexHash(c)}
	copy(key.CommitHash[:], commitHashOf(c))
	return key
}

func TestTallyBtcBlockVotes(t *testing.T) {
	t.Run("counts power per attested block", func(t *testing.T) {
		ext := voteExt(t, btcVote(10, 'a'), btcVote(11, 'b'))
		power, total := keeper.TallyBtcBlockVotes(unsignedCommit(
			commitVote(40, ext),
			commitVote(30, voteExt(t, btcVote(10, 'a'))),
			commitVote(30, nil),
		), 10)
		require.Equal(t, int64(100), total)
		require.Equal(t, map[keeper.BtcVoteKey]int64{voteKey('a'): 70}, power)

		power, _ = keeper.TallyBtcBlockVotes(unsignedCommit(commitVote(40, ext)), 11)
		require.Equal(t, map[keeper.BtcVoteKey]int64{voteKey('b'): 40}, power)
	})

	t.Run("split votes", func(t *testing.T) {
		power, total := keeper.TallyBtcBlockVotes(unsignedCommit(
			commitVote(50, voteExt(t, btcVote(10, 'a'))),
			commitVote(30, voteExt(t, btcVote(10, 'b'))),
			commitVote(20, voteExt(t, btcVote(10, 'c'))),
		), 10)
		require.Equal(t, int64(100), total)
		require.Equal(t, map[keeper.BtcVoteKey]int64{voteKey('a'): 50, voteKey('b'): 30, voteKey('c'): 20}, power)
	})

	t.Run("same hash with another commit hash is another vote", func(t *testing.T) {
		other := &types.BtcBlockVote{Height: 10, Hash: hexHash('a'), CommitHash: commitHashOf('z')}
		power, _ := keeper.TallyBtcBlockVotes(unsignedCommit(
			commitVote(60, voteExt(t, btcVote(10, 'a'))),
			commitVote(40, voteExt(t, other)),
		), 10)
		require.Len(t, power, 2)
		require.Equal(t, int64(60), power[voteKey('a')])
	})

	t.Run("votes that are not commit votes only add to the total", func(t *testing.T) {
		ext := voteExt(t, btcVote(10, 'a'))
		nilVote := commitVote(30, ext)
		nilVote.BlockIdFlag = cmtproto.BlockIDFlagNil
		absent := commitVote(20, ext)
		absent.BlockIdFlag = cmtproto.BlockIDFlagAbsent
		power, total := keeper.TallyBtcBlockVotes(unsignedCommit(commitVote(50, ext), nilVote, absent), 10)
		require.Equal(t, int64(100), total)
		require.Equal(t, map[keeper.BtcVoteKey]int64{voteKey('a'): 50}, power)
	})

	t.Run("a validator counts once per height", func(t *testing.T) {
		// the first vote for the height counts, the repeated one does not
		dup := voteExt(t, btcVote(10, 'a'), btcVote(10, 'b'))
		power, total := keeper.TallyBtcBlockVotes(unsignedCommit(commitVote(100, dup)), 10)
		require.Equal(t, int64(100), total)
		require.Equal(t, map[keeper.BtcVoteKey]int64{voteKey('a'): 100}, power)
	})

	t.Run("undecodable extensions and short commit hashes do not count", func(t *testing.T) {
		short := &types.BtcBlockVote{Height: 10, Hash: hexHash('a'), CommitHash: []byte{1, 2}}
		power, total := keeper.TallyBtcBlockVotes(unsignedCommit(
			commitVote(40, []byte{0xff, 0xff, 0xff}),
			commitVote(30, voteExt(t, short)),
			commitVote(30, voteExt(t, btcVote(10, 'a'))),
		), 10)
		require.Equal(t, int64(100), total)
		require.Equal(t, map[keeper.BtcVoteKey]int64{voteKey('a'): 30}, power)
	})

	t.Run("an oversized extension does not count", func(t *testing.T) {
		// decodable, but larger than VerifyVoteExtension accepts: only the
		// proposer can put it in a commit
		ext := voteExt(t, btcVote(10, 'a'))
		big := protowire.AppendTag(ext, 15, protowire.BytesType)
		big = protowire.AppendBytes(big, make([]byte, types.MaxVoteExtensionSize))
		power, total := keeper.TallyBtcBlockVotes(unsignedCommit(commitVote(60, big), commitVote(40, ext)), 10)
		require.Equal(t, int64(100), total)
		require.Equal(t, map[keeper.BtcVoteKey]int64{voteKey('a'): 40}, power)
	})
}

func TestHasSupermajority(t *testing.T) {
	require.True(t, keeper.HasSupermajority(67, 100))
	require.False(t, keeper.HasSupermajority(66, 100), "66 of 100 is below 2/3")
	require.False(t, keeper.HasSupermajority(2, 3), "exactly 2/3 is not more than 2/3")
	require.True(t, keeper.HasSupermajority(3, 3))
	require.False(t, keeper.HasSupermajority(0, 0))
	require.False(t, keeper.HasSupermajority(1, 0))
}

// voteFixture is a fixture with several validators, so the power can be split.
type voteFixture struct {
	*fixture
	keys []mldsa.PrivKey
}

// newVoteFixture adds validators to the fixture; keys[0] is the fixture's own.
func newVoteFixture(t *testing.T, extra int) *voteFixture {
	t.Helper()
	f := initFixture(t)
	vf := &voteFixture{fixture: f, keys: []mldsa.PrivKey{f.privateKey}}
	for range extra {
		key := mldsa.GenPrivKey()
		pub, err := cryptoenc.PubKeyToProto(key.PubKey())
		require.NoError(t, err)
		f.consPubKeys[string(key.PubKey().Address())] = pub
		vf.keys = append(vf.keys, key)
	}
	return vf
}

// msgWithCommit returns a message for block with the extended commit of votes,
// and sets f.ctx to the context that carries it.
func (vf *voteFixture) msgWithCommit(t *testing.T, msg *types.MsgBtcBlock, votes []qbtctestutil.TestVote) *types.MsgBtcBlock {
	t.Helper()
	ec := qbtctestutil.NewExtendedCommit(voteChainID, voteHeight, 0, votes)
	bz, err := ec.Marshal()
	require.NoError(t, err)
	msg.ExtendedCommitInfo = bz
	vf.setLastCommit(ec)
	return msg
}

func (vf *voteFixture) validate(msg *types.MsgBtcBlock) error {
	return vf.keeper.ValidateBtcBlockVotes(sdk.UnwrapSDKContext(vf.ctx), msg)
}

// setupWithChain returns a fixture with four validators, its regtest chain, and
// a message with the next block and the vote extension that attests it.
func setupWithChain(t *testing.T) (*voteFixture, *regtestChain, *types.MsgBtcBlock, []byte) {
	t.Helper()
	vf := newVoteFixture(t, 3)
	c := newRegtestChain(t, vf.fixture, 800000)
	b1 := c.nextBlock(c.coinbase())
	msg := &types.MsgBtcBlock{
		Blocks: []*types.BtcBlock{blockOf(t, 800001, b1)},
		Signer: types.BtcBlockSignerAddress,
	}
	return vf, c, msg, blockVotes(t, msg.Blocks)
}

func TestValidateBtcBlockVotes(t *testing.T) {
	setup := func(t *testing.T) (*voteFixture, *types.MsgBtcBlock, []byte) {
		vf, _, msg, ext := setupWithChain(t)
		return vf, msg, ext
	}
	votesFor := func(vf *voteFixture, ext []byte, powers ...int64) []qbtctestutil.TestVote {
		votes := make([]qbtctestutil.TestVote, len(powers))
		for i, p := range powers {
			votes[i] = qbtctestutil.TestVote{Key: vf.keys[i], Power: p, Extension: ext}
		}
		return votes
	}

	t.Run("valid", func(t *testing.T) {
		vf, msg, ext := setup(t)
		// 40+30 = 70 of 100 attest the block, 30 attest nothing
		vf.msgWithCommit(t, msg, append(votesFor(vf, ext, 40, 30), qbtctestutil.TestVote{Key: vf.keys[2], Power: 30}))
		require.NoError(t, vf.validate(msg))
	})

	t.Run("exactly 2/3 is not enough", func(t *testing.T) {
		vf, msg, ext := setup(t)
		vf.msgWithCommit(t, msg, append(votesFor(vf, ext, 40, 20), qbtctestutil.TestVote{Key: vf.keys[2], Power: 30}, qbtctestutil.TestVote{Key: vf.keys[3], Power: 10}))
		// 60 of 100
		require.ErrorContains(t, vf.validate(msg), "insufficient vote extension power: 60 of 100")

		vf, msg, ext = setup(t)
		vf.msgWithCommit(t, msg, append(votesFor(vf, ext, 2), qbtctestutil.TestVote{Key: vf.keys[1], Power: 1}))
		require.ErrorContains(t, vf.validate(msg), "insufficient vote extension power: 2 of 3")
	})

	t.Run("wrong commit hash", func(t *testing.T) {
		vf, msg, _ := setup(t)
		wrong := voteExt(t, &types.BtcBlockVote{Height: 800001, Hash: msg.Blocks[0].Hash, CommitHash: commitHashOf('x')})
		vf.msgWithCommit(t, msg, votesFor(vf, wrong, 100))
		require.ErrorContains(t, vf.validate(msg), "insufficient vote extension power")
	})

	t.Run("wrong hash", func(t *testing.T) {
		vf, msg, ext := setup(t)
		vf.msgWithCommit(t, msg, votesFor(vf, ext, 100))
		msg.Blocks[0].Hash = hexHash('c')
		require.ErrorContains(t, vf.validate(msg), "insufficient vote extension power")
	})

	t.Run("content other than attested", func(t *testing.T) {
		vf, c, msg, ext := setupWithChain(t)
		vf.msgWithCommit(t, msg, votesFor(vf, ext, 100))
		msg.Blocks[0].BlockContent = blockOf(t, 800001, c.nextBlock(c.coinbase(1))).BlockContent
		require.ErrorContains(t, vf.validate(msg), "insufficient vote extension power")
	})

	t.Run("forged extension signature", func(t *testing.T) {
		vf, msg, ext := setup(t)
		ec := qbtctestutil.NewExtendedCommit(voteChainID, voteHeight, 0, votesFor(vf, ext, 100))
		// the signature is for another extension
		ec.Votes[0].ExtensionSignature = qbtctestutil.NewExtendedCommit(voteChainID, voteHeight, 0, votesFor(vf, nil, 100)).Votes[0].ExtensionSignature
		bz, err := ec.Marshal()
		require.NoError(t, err)
		msg.ExtendedCommitInfo = bz
		vf.setLastCommit(ec)
		require.ErrorContains(t, vf.validate(msg), "failed to verify validator")
	})

	t.Run("extension signed for another height", func(t *testing.T) {
		vf, msg, ext := setup(t)
		ec := qbtctestutil.NewExtendedCommit(voteChainID, voteHeight+1, 0, votesFor(vf, ext, 100))
		bz, err := ec.Marshal()
		require.NoError(t, err)
		msg.ExtendedCommitInfo = bz
		vf.setLastCommit(ec)
		require.ErrorContains(t, vf.validate(msg), "failed to verify validator")
	})

	t.Run("extension signed for another chain", func(t *testing.T) {
		vf, msg, ext := setup(t)
		ec := qbtctestutil.NewExtendedCommit("other-chain", voteHeight, 0, votesFor(vf, ext, 100))
		bz, err := ec.Marshal()
		require.NoError(t, err)
		msg.ExtendedCommitInfo = bz
		vf.setLastCommit(ec)
		require.ErrorContains(t, vf.validate(msg), "failed to verify validator")
	})

	t.Run("extension of a key that is not the validator's", func(t *testing.T) {
		vf, msg, ext := setup(t)
		votes := votesFor(vf, ext, 100)
		// signed by an outsider that claims the validator's address
		impostor := qbtctestutil.NewExtendedCommit(voteChainID, voteHeight, 0, []qbtctestutil.TestVote{{Key: mldsa.GenPrivKey(), Power: 100, Extension: ext}})
		ec := qbtctestutil.NewExtendedCommit(voteChainID, voteHeight, 0, votes)
		ec.Votes[0].ExtensionSignature = impostor.Votes[0].ExtensionSignature
		bz, err := ec.Marshal()
		require.NoError(t, err)
		msg.ExtendedCommitInfo = bz
		vf.setLastCommit(ec)
		require.ErrorContains(t, vf.validate(msg), "failed to verify validator")
	})

	t.Run("commit that is not the block's last commit", func(t *testing.T) {
		vf, msg, ext := setup(t)
		// the message carries a commit in which validator 1 voted with all the power
		vf.msgWithCommit(t, msg, votesFor(vf, ext, 100))
		forgedEC := qbtctestutil.NewExtendedCommit(voteChainID, voteHeight, 0, []qbtctestutil.TestVote{
			{Key: vf.keys[1], Power: 100, Extension: ext},
		})
		bz, err := forgedEC.Marshal()
		require.NoError(t, err)
		msg.ExtendedCommitInfo = bz
		// the context still holds the real last commit
		require.ErrorContains(t, vf.validate(msg), "does not match last commit")
	})

	t.Run("inflated power does not match the last commit", func(t *testing.T) {
		vf, msg, ext := setup(t)
		vf.msgWithCommit(t, msg, votesFor(vf, ext, 40, 30))
		inflated := qbtctestutil.NewExtendedCommit(voteChainID, voteHeight, 0, votesFor(vf, ext, 400, 30))
		bz, err := inflated.Marshal()
		require.NoError(t, err)
		msg.ExtendedCommitInfo = bz
		require.ErrorContains(t, vf.validate(msg), "does not match last commit")
	})

	t.Run("signatures cover less than 2/3 of the power", func(t *testing.T) {
		vf, msg, ext := setup(t)
		// 50 signed the attestation, 50 did not vote
		votes := append(votesFor(vf, ext, 50), qbtctestutil.TestVote{Key: vf.keys[1], Power: 50, Flag: cmtproto.BlockIDFlagAbsent})
		vf.msgWithCommit(t, msg, votes)
		require.ErrorContains(t, vf.validate(msg), "insufficient cumulative voting power")
	})

	t.Run("a commit vote without an extension signature", func(t *testing.T) {
		vf, msg, ext := setup(t)
		votes := append(votesFor(vf, ext, 50), qbtctestutil.TestVote{Key: vf.keys[1], Power: 50, Extension: ext})
		ec := qbtctestutil.NewExtendedCommit(voteChainID, voteHeight, 0, votes)
		ec.Votes[1].ExtensionSignature = nil
		bz, err := ec.Marshal()
		require.NoError(t, err)
		msg.ExtendedCommitInfo = bz
		vf.setLastCommit(ec)
		require.ErrorContains(t, vf.validate(msg), "empty vote extension signature")
	})

	t.Run("not decodable", func(t *testing.T) {
		vf, msg, ext := setup(t)
		vf.msgWithCommit(t, msg, votesFor(vf, ext, 100))
		msg.ExtendedCommitInfo = []byte{0xff, 0xff}
		require.ErrorContains(t, vf.validate(msg), "decode extended commit info")
	})

	t.Run("vote extensions not enabled", func(t *testing.T) {
		vf, msg, ext := setup(t)
		vf.msgWithCommit(t, msg, votesFor(vf, ext, 100))
		disabled := qbtctestutil.ContextWithLastCommit(sdk.UnwrapSDKContext(vf.ctx), voteChainID, voteHeight, 0, abci.ExtendedCommitInfo{})
		require.ErrorContains(t, vf.keeper.ValidateBtcBlockVotes(disabled, msg), "not enabled")
		// enabled at the block's own height: its last commit has no extensions yet
		atEnable := qbtctestutil.ContextWithLastCommit(sdk.UnwrapSDKContext(vf.ctx), voteChainID, voteHeight, voteHeight, abci.ExtendedCommitInfo{})
		require.ErrorContains(t, vf.keeper.ValidateBtcBlockVotes(atEnable, msg), "not enabled")
	})
}

func TestVoteExtensionsEnabled(t *testing.T) {
	f := initFixture(t)
	ctx := sdk.UnwrapSDKContext(f.ctx)
	at := func(height, enable int64) bool {
		return keeper.VoteExtensionsEnabled(qbtctestutil.ContextWithLastCommit(ctx, voteChainID, height, enable, abci.ExtendedCommitInfo{}))
	}
	require.False(t, at(10, 0), "disabled")
	require.False(t, at(10, 10), "the votes of the enable height itself have no extensions")
	require.True(t, at(11, 10))
	require.False(t, at(5, 10))
	require.False(t, keeper.VoteExtensionsEnabled(ctx), "no consensus params")
}

func TestSetMsgReportBlock_MultipleBlocks(t *testing.T) {
	f, c := setupAuthTest(t)
	b1, coinbase1, spend1 := authTestBlock(t, c)
	// the second block extends the first, so mine it on a tip that is the first header
	c2 := *c
	c2.tip = b1.Header
	c2.height = c.height + 1
	b2 := c2.nextBlock(c2.coinbase(312_500_000), spendTx([]wire.OutPoint{{Hash: spend1.TxHash(), Index: 0}}, p2pkhOut(t, 80_000)))
	b2Spend := b2.Transactions[1]

	msg := attestedBlocksMsg(t, f, c.height+1, b1, b2)
	require.NoError(t, submitBlockMsg(f, msg))

	require.Equal(t, uint64(800002), getLastProcessed(t, f))
	require.Equal(t, uint64(312_490_000), getTestEntitlement(t, f, coinbase1.TxHash().String(), 0), "the block's fee is deducted")
	// the first block's output was spent by the second
	_, err := f.keeper.Utxoes.Get(f.ctx, spend1.TxHash().String()+"-0")
	require.Error(t, err)
	require.Equal(t, uint64(80_000), getTestEntitlement(t, f, b2Spend.TxHash().String(), 0))
}

func TestSetMsgReportBlock_IsAtomic(t *testing.T) {
	f, c := setupAuthTest(t)
	b1, coinbase1, _ := authTestBlock(t, c)
	// the second block does not link to the first
	c2 := *c
	b2 := c2.nextBlock(c2.coinbase(1))

	msg := attestedBlocksMsg(t, f, c.height+1, b1, b2)
	require.ErrorContains(t, submitBlockMsg(f, msg), "not on the last processed block")

	// the first block, valid on its own, left no trace
	require.Equal(t, uint64(800000), getLastProcessed(t, f))
	_, err := f.keeper.Utxoes.Get(f.ctx, coinbase1.TxHash().String()+"-0")
	require.Error(t, err)
	require.Equal(t, uint64(100_000), getTestEntitlement(t, f, authTestInput, 0), "the input is not spent")
}

func TestSetMsgReportBlock_RejectsGapInHeights(t *testing.T) {
	f, c := setupAuthTest(t)
	b1, _, _ := authTestBlock(t, c)
	c2 := *c
	c2.tip = b1.Header
	b2 := c2.nextBlock(c2.coinbase())

	msg := attestedBlocksMsg(t, f, c.height+1, b1, b2)
	msg.Blocks[1].Height++
	attest(t, f, msg)
	require.ErrorContains(t, submitBlockMsg(f, msg), "is not the next block height")
	require.Equal(t, uint64(800000), getLastProcessed(t, f))
}

func TestSetMsgReportBlock_RequiresVoteExtensions(t *testing.T) {
	f, c := setupAuthTest(t)
	block, _, _ := authTestBlock(t, c)
	msg := attestedBlockMsg(t, f, c.height+1, block)
	f.ctx = qbtctestutil.ContextWithLastCommit(sdk.UnwrapSDKContext(f.ctx), voteChainID, voteHeight, 0, abci.ExtendedCommitInfo{})

	require.ErrorContains(t, submitBlockMsg(f, msg), "vote extensions")
	require.Equal(t, uint64(800000), getLastProcessed(t, f))
}

func TestSetMsgReportBlock_RejectsMalformedMessage(t *testing.T) {
	cases := map[string]func(msg *types.MsgBtcBlock){
		"no blocks":             func(msg *types.MsgBtcBlock) { msg.Blocks = nil },
		"block without hash":    func(msg *types.MsgBtcBlock) { msg.Blocks[0].Hash = "" },
		"block without content": func(msg *types.MsgBtcBlock) { msg.Blocks[0].BlockContent = nil },
		"no extended commit":    func(msg *types.MsgBtcBlock) { msg.ExtendedCommitInfo = nil },
		"too many blocks": func(msg *types.MsgBtcBlock) {
			msg.Blocks = append(msg.Blocks, make([]*types.BtcBlock, types.MaxBtcBlocksPerMsg)...)
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			f, c := setupAuthTest(t)
			block, _, _ := authTestBlock(t, c)
			msg := attestedBlockMsg(t, f, c.height+1, block)
			mutate(msg)
			require.ErrorContains(t, submitBlockMsg(f, msg), "invalid MsgBtcBlock")
			require.Equal(t, uint64(800000), getLastProcessed(t, f))
		})
	}
}
