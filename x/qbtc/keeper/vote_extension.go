package keeper

import (
	"fmt"

	abci "github.com/cometbft/cometbft/abci/types"
	cmtproto "github.com/cometbft/cometbft/proto/tendermint/types"
	"github.com/cosmos/cosmos-sdk/baseapp"
	sdk "github.com/cosmos/cosmos-sdk/types"

	"github.com/btcq-org/qbtc/x/qbtc/types"
)

// BtcVoteKey identifies what validators attest for one Bitcoin height: the
// block hash and the hash of its uncompressed commit.
type BtcVoteKey struct {
	Hash       string
	CommitHash [types.BtcCommitHashSize]byte
}

// VoteExtensionsEnabled reports whether the votes of the previous height carry
// vote extensions, so a proposal or block at the context's height can use them.
// It is the condition under which baseapp.ValidateVoteExtensions checks the
// extension signatures.
func VoteExtensionsEnabled(ctx sdk.Context) bool {
	cp := ctx.ConsensusParams()
	return cp.Abci != nil && cp.Abci.VoteExtensionsEnableHeight != 0 && ctx.HeaderInfo().Height > cp.Abci.VoteExtensionsEnableHeight
}

// TallyBtcBlockVotes returns, for each (hash, commit hash) attested at the
// Bitcoin height, the voting power behind it, and the total power of the
// commit. The total counts every vote, as baseapp.ValidateVoteExtensions does.
// Only commit votes with a decodable extension of at most
// types.MaxVoteExtensionSize bytes count (VerifyVoteExtension rejects larger
// ones, so one in a commit was put there by the proposer); a validator counts
// once per height, with its first vote for that height.
func TallyBtcBlockVotes(extCommit abci.ExtendedCommitInfo, height uint64) (map[BtcVoteKey]int64, int64) {
	power := make(map[BtcVoteKey]int64)
	var total int64
	for _, vote := range extCommit.Votes {
		total += vote.Validator.Power
		if vote.BlockIdFlag != cmtproto.BlockIDFlagCommit || len(vote.VoteExtension) == 0 || len(vote.VoteExtension) > types.MaxVoteExtensionSize {
			continue
		}
		var ext types.BtcBlockVoteExtension
		if err := ext.Unmarshal(vote.VoteExtension); err != nil {
			continue
		}
		for _, v := range ext.Votes {
			if v == nil || v.Height != height {
				continue
			}
			if len(v.CommitHash) == types.BtcCommitHashSize {
				key := BtcVoteKey{Hash: v.Hash}
				copy(key.CommitHash[:], v.CommitHash)
				power[key] += vote.Validator.Power
			}
			break
		}
	}
	return power, total
}

// HasSupermajority reports whether power is more than 2/3 of total.
func HasSupermajority(power, total int64) bool {
	return total > 0 && power > 0 && power*3 > total*2
}

// ValidateBtcBlockVotes checks that msg carries the previous height's extended
// commit with valid vote extension signatures, and that validators with more
// than 2/3 of the voting power attested each of its blocks, with exactly the
// block's hash and content.
func (k Keeper) ValidateBtcBlockVotes(ctx sdk.Context, msg *types.MsgBtcBlock) error {
	if !VoteExtensionsEnabled(ctx) {
		return fmt.Errorf("vote extensions are not enabled at height %d", ctx.HeaderInfo().Height)
	}
	var extCommit abci.ExtendedCommitInfo
	if err := extCommit.Unmarshal(msg.ExtendedCommitInfo); err != nil {
		return fmt.Errorf("decode extended commit info: %w", err)
	}
	// The fork ignores the height and chain ID arguments and takes them from the
	// context. It checks that extCommit matches this block's last commit
	// (round, validators, powers, order), every commit vote's extension
	// signature (bound to the chain ID, the previous height and the round), and
	// that signed votes carry more than 2/3 of the power.
	if err := baseapp.ValidateVoteExtensions(ctx, k.stakingKeeper, 0, "", extCommit); err != nil {
		return fmt.Errorf("invalid vote extensions: %w", err)
	}
	for _, block := range msg.Blocks {
		signBytes, _, err := types.DecodeBtcBlockContent(block.BlockContent)
		if err != nil {
			return fmt.Errorf("block %d: invalid content: %w", block.Height, err)
		}
		power, total := TallyBtcBlockVotes(extCommit, block.Height)
		got := power[BtcVoteKey{Hash: block.Hash, CommitHash: types.BtcCommitHash(signBytes)}]
		if !HasSupermajority(got, total) {
			return fmt.Errorf("block %d: insufficient vote extension power: %d of %d", block.Height, got, total)
		}
	}
	return nil
}
