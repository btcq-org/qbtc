package keeper_test

import (
	"testing"

	abci "github.com/cometbft/cometbft/abci/types"
	cmtproto "github.com/cometbft/cometbft/proto/tendermint/types"
	"github.com/stretchr/testify/require"

	"github.com/btcq-org/qbtc/x/qbtc/keeper"
	"github.com/btcq-org/qbtc/x/qbtc/types"
)

func voteExt(t *testing.T, items ...*types.BtcBlockAttest) []byte {
	t.Helper()
	bz, err := (&types.BtcBlockVoteExtension{Items: items}).Marshal()
	require.NoError(t, err)
	return bz
}

func commitVote(addr string, power int64, ext []byte) abci.ExtendedVoteInfo {
	return abci.ExtendedVoteInfo{
		Validator:     abci.Validator{Address: []byte(addr), Power: power},
		BlockIdFlag:   cmtproto.BlockIDFlagCommit,
		VoteExtension: ext,
	}
}

func TestTallyBtcBlockDelta(t *testing.T) {
	hashA, deltaA := []byte("hash-A"), make([]byte, 32)
	deltaA[0] = 0xAA
	hashB, deltaB := []byte("hash-B"), make([]byte, 32)
	deltaB[0] = 0xBB
	attA := &types.BtcBlockAttest{Height: 5, BlockHash: hashA, DeltaHash: deltaA}
	attB := &types.BtcBlockAttest{Height: 5, BlockHash: hashB, DeltaHash: deltaB}

	t.Run("supermajority picks the agreed digest", func(t *testing.T) {
		ec := abci.ExtendedCommitInfo{Votes: []abci.ExtendedVoteInfo{
			commitVote("v1", 10, voteExt(t, attA)),
			commitVote("v2", 10, voteExt(t, attA)),
			commitVote("v3", 10, voteExt(t, attA)),
			commitVote("v4", 10, voteExt(t, attB)),
		}}
		hash, dh, power, total := keeper.TallyBtcBlockDelta(ec, 5)
		require.Equal(t, int64(40), total)
		require.Equal(t, int64(30), power)
		require.Equal(t, hashA, hash)
		require.Equal(t, deltaA, dh)
		require.Greater(t, power*3, total*2) // 90 > 80 → supermajority
	})

	t.Run("exactly two-thirds is not a supermajority", func(t *testing.T) {
		ec := abci.ExtendedCommitInfo{Votes: []abci.ExtendedVoteInfo{
			commitVote("v1", 10, voteExt(t, attA)),
			commitVote("v2", 10, voteExt(t, attA)),
			commitVote("v3", 10, voteExt(t, attB)),
		}}
		_, _, power, total := keeper.TallyBtcBlockDelta(ec, 5)
		require.Equal(t, int64(20), power)
		require.Equal(t, int64(30), total)
		require.False(t, power*3 > total*2) // 60 > 60 is false
	})

	t.Run("non-commit votes contribute to total but not to power", func(t *testing.T) {
		nilVote := commitVote("v3", 10, voteExt(t, attA))
		nilVote.BlockIdFlag = cmtproto.BlockIDFlagNil
		ec := abci.ExtendedCommitInfo{Votes: []abci.ExtendedVoteInfo{
			commitVote("v1", 10, voteExt(t, attA)),
			commitVote("v2", 10, voteExt(t, attA)),
			nilVote,
		}}
		_, _, power, total := keeper.TallyBtcBlockDelta(ec, 5)
		require.Equal(t, int64(20), power)
		require.Equal(t, int64(30), total)
	})

	t.Run("a validator is counted once per height", func(t *testing.T) {
		dup := voteExt(t, attA, &types.BtcBlockAttest{Height: 5, BlockHash: hashA, DeltaHash: deltaA})
		ec := abci.ExtendedCommitInfo{Votes: []abci.ExtendedVoteInfo{
			commitVote("v1", 10, dup),
		}}
		_, _, power, _ := keeper.TallyBtcBlockDelta(ec, 5)
		require.Equal(t, int64(10), power)
	})

	t.Run("no votes for the target height", func(t *testing.T) {
		ec := abci.ExtendedCommitInfo{Votes: []abci.ExtendedVoteInfo{
			commitVote("v1", 10, voteExt(t, attA)),
		}}
		_, _, power, _ := keeper.TallyBtcBlockDelta(ec, 99)
		require.Equal(t, int64(0), power)
	})
}
