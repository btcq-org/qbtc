package testutil

import (
	"bytes"
	"slices"

	"cosmossdk.io/core/comet"
	abci "github.com/cometbft/cometbft/abci/types"
	"github.com/cometbft/cometbft/crypto/mldsa"
	cmtproto "github.com/cometbft/cometbft/proto/tendermint/types"
	sdk "github.com/cosmos/cosmos-sdk/types"
	protoio "github.com/cosmos/gogoproto/io"

	coreheader "cosmossdk.io/core/header"
)

// TestVote is one validator's vote in a test extended commit.
type TestVote struct {
	Key       mldsa.PrivKey
	Power     int64
	Extension []byte
	// Flag defaults to a commit vote.
	Flag cmtproto.BlockIDFlag
}

func (v TestVote) flag() cmtproto.BlockIDFlag {
	if v.Flag == cmtproto.BlockIDFlagUnknown {
		return cmtproto.BlockIDFlagCommit
	}
	return v.Flag
}

// VoteExtensionSignBytes returns the bytes CometBFT has validators sign for a
// vote extension at height, and baseapp.ValidateVoteExtensions verifies.
func VoteExtensionSignBytes(chainID string, height int64, round int32, extension []byte) []byte {
	cve := cmtproto.CanonicalVoteExtension{
		Extension: extension,
		Height:    height,
		Round:     int64(round),
		ChainId:   chainID,
	}
	var buf bytes.Buffer
	if err := protoio.NewDelimitedWriter(&buf).WriteMsg(&cve); err != nil {
		panic(err)
	}
	return buf.Bytes()
}

// NewExtendedCommit builds the extended commit a proposer at proposalHeight
// receives: the votes of the previous height, sorted as CometBFT sorts them
// (by power, then address) with every commit vote's extension signed.
func NewExtendedCommit(chainID string, proposalHeight int64, round int32, votes []TestVote) abci.ExtendedCommitInfo {
	sorted := slices.Clone(votes)
	slices.SortFunc(sorted, func(a, b TestVote) int {
		if a.Power != b.Power {
			return int(b.Power - a.Power)
		}
		return bytes.Compare(a.Key.PubKey().Address(), b.Key.PubKey().Address())
	})
	ec := abci.ExtendedCommitInfo{Round: round}
	for _, v := range sorted {
		info := abci.ExtendedVoteInfo{
			Validator:   abci.Validator{Address: v.Key.PubKey().Address(), Power: v.Power},
			BlockIdFlag: v.flag(),
		}
		if v.flag() == cmtproto.BlockIDFlagCommit {
			sig, err := v.Key.Sign(VoteExtensionSignBytes(chainID, proposalHeight-1, round, v.Extension))
			if err != nil {
				panic(err)
			}
			info.VoteExtension = v.Extension
			info.ExtensionSignature = sig
		}
		ec.Votes = append(ec.Votes, info)
	}
	return ec
}

// ContextWithLastCommit returns ctx as the block at proposalHeight sees it:
// with the chain ID, the commit of the previous height, and vote extensions
// enabled from enableHeight (0 disables them).
func ContextWithLastCommit(ctx sdk.Context, chainID string, proposalHeight, enableHeight int64, ec abci.ExtendedCommitInfo) sdk.Context {
	return ctx.
		WithHeaderInfo(coreheader.Info{Height: proposalHeight, ChainID: chainID}).
		WithCometInfo(testBlockInfo{lastCommit: testCommitInfo{ec}}).
		WithConsensusParams(cmtproto.ConsensusParams{
			Abci: &cmtproto.ABCIParams{VoteExtensionsEnableHeight: enableHeight},
		})
}

type testBlockInfo struct{ lastCommit comet.CommitInfo }

func (b testBlockInfo) GetEvidence() comet.EvidenceList { return nil }
func (b testBlockInfo) GetValidatorsHash() []byte       { return nil }
func (b testBlockInfo) GetProposerAddress() []byte      { return nil }
func (b testBlockInfo) GetLastCommit() comet.CommitInfo { return b.lastCommit }

type testCommitInfo struct{ ec abci.ExtendedCommitInfo }

func (c testCommitInfo) Round() int32           { return c.ec.Round }
func (c testCommitInfo) Votes() comet.VoteInfos { return testVoteInfos(c.ec.Votes) }

type testVoteInfos []abci.ExtendedVoteInfo

func (v testVoteInfos) Len() int                 { return len(v) }
func (v testVoteInfos) Get(i int) comet.VoteInfo { return testVoteInfo{v[i]} }

type testVoteInfo struct{ info abci.ExtendedVoteInfo }

func (v testVoteInfo) Validator() comet.Validator { return testValidator{v.info.Validator} }
func (v testVoteInfo) GetBlockIDFlag() comet.BlockIDFlag {
	return comet.BlockIDFlag(v.info.BlockIdFlag)
}

type testValidator struct{ val abci.Validator }

func (v testValidator) Address() []byte { return v.val.Address }
func (v testValidator) Power() int64    { return v.val.Power }
