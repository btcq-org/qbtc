package types_test

import (
	"strings"
	"testing"

	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/stretchr/testify/require"

	"github.com/btcq-org/qbtc/common"
	"github.com/btcq-org/qbtc/x/qbtc/types"
)

func validBtcBlockMsg() *types.MsgBtcBlock {
	return &types.MsgBtcBlock{
		Blocks:             []*types.BtcBlock{{Height: 1, Hash: strings.Repeat("a", 64), BlockContent: []byte{1}}},
		ExtendedCommitInfo: []byte{1},
		Signer:             types.BtcBlockSignerAddress,
	}
}

func TestMsgBtcBlockValidateBasic(t *testing.T) {
	sdk.GetConfig().SetBech32PrefixForAccount(common.AccountAddressPrefix, common.AccountAddressPrefix+sdk.PrefixPublic)
	require.NoError(t, validBtcBlockMsg().ValidateBasic())

	cases := map[string]func(m *types.MsgBtcBlock){
		"no blocks":                func(m *types.MsgBtcBlock) { m.Blocks = nil },
		"too many blocks":          func(m *types.MsgBtcBlock) { m.Blocks = make([]*types.BtcBlock, types.MaxBtcBlocksPerMsg+1) },
		"nil block":                func(m *types.MsgBtcBlock) { m.Blocks = []*types.BtcBlock{nil} },
		"block without hash":       func(m *types.MsgBtcBlock) { m.Blocks[0].Hash = "" },
		"block without content":    func(m *types.MsgBtcBlock) { m.Blocks[0].BlockContent = nil },
		"no extended commit":       func(m *types.MsgBtcBlock) { m.ExtendedCommitInfo = nil },
		"no signer":                func(m *types.MsgBtcBlock) { m.Signer = "" },
		"signer is not an address": func(m *types.MsgBtcBlock) { m.Signer = "nobody" },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			msg := validBtcBlockMsg()
			mutate(msg)
			require.Error(t, msg.ValidateBasic())
		})
	}

	max := validBtcBlockMsg()
	for len(max.Blocks) < types.MaxBtcBlocksPerMsg {
		max.Blocks = append(max.Blocks, max.Blocks[0])
	}
	require.NoError(t, max.ValidateBasic())
}

func TestBtcBlockVoteExtensionValidateFormat(t *testing.T) {
	vote := func(height uint64) *types.BtcBlockVote {
		return &types.BtcBlockVote{Height: height, Hash: strings.Repeat("0f", 32), CommitHash: make([]byte, types.BtcCommitHashSize)}
	}
	require.NoError(t, (&types.BtcBlockVoteExtension{}).ValidateFormat())
	require.NoError(t, (&types.BtcBlockVoteExtension{Votes: []*types.BtcBlockVote{vote(1), vote(2)}}).ValidateFormat())
	require.Error(t, (&types.BtcBlockVoteExtension{Votes: []*types.BtcBlockVote{vote(1), vote(1)}}).ValidateFormat())
	require.Error(t, (&types.BtcBlockVoteExtension{Votes: []*types.BtcBlockVote{nil}}).ValidateFormat())
	bad := vote(1)
	bad.Hash = strings.Repeat("0F", 32)
	require.Error(t, (&types.BtcBlockVoteExtension{Votes: []*types.BtcBlockVote{bad}}).ValidateFormat())
}
