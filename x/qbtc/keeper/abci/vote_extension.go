package abci

import (
	"fmt"

	abci "github.com/cometbft/cometbft/abci/types"
	sdk "github.com/cosmos/cosmos-sdk/types"

	"github.com/btcq-org/qbtc/x/qbtc/types"
)

// ExtendVote attests the Bitcoin blocks this node has read, checked and cached:
// consecutive heights from the next unprocessed one, at most
// types.MaxBtcBlockVotes. The extension is empty if there are none.
//
// The context holds the state before the block being voted on, so the next
// unprocessed height ignores what that block processes. The attested heights
// reach past them (MaxBtcBlockVotes is twice MaxBtcBlocksPerMsg), so the
// proposer of the following block still has attested blocks to inject.
func (h *ProposalHandler) ExtendVote(ctx sdk.Context, _ *abci.RequestExtendVote) (*abci.ResponseExtendVote, error) {
	lastProcessedBlock, err := h.keeper.GetLastProcessedBlock(ctx)
	if err != nil {
		return nil, err
	}
	var ext types.BtcBlockVoteExtension
	for _, block := range h.reader.CachedBlocks(lastProcessedBlock+1, types.MaxBtcBlockVotes) {
		ext.Votes = append(ext.Votes, &types.BtcBlockVote{
			Height:     block.Height,
			Hash:       block.Hash,
			CommitHash: block.CommitHash[:],
		})
	}
	var bz []byte
	if len(ext.Votes) > 0 {
		if bz, err = ext.Marshal(); err != nil {
			return nil, err
		}
	}
	ctx.Logger().Info("btc vote extension", "votes", len(ext.Votes), "bytes", len(bz))
	return &abci.ResponseExtendVote{VoteExtension: bz}, nil
}

// VerifyVoteExtension checks only the format of a vote extension. It must
// not depend on local state, in particular not on this node's view of Bitcoin:
// validators that disagree on a vote extension's validity can halt the chain.
// Whether enough validators attested a block is decided when the extensions are
// tallied.
func (h *ProposalHandler) VerifyVoteExtension(ctx sdk.Context, req *abci.RequestVerifyVoteExtension) (*abci.ResponseVerifyVoteExtension, error) {
	if err := validateVoteExtension(req.VoteExtension); err != nil {
		ctx.Logger().Info("rejecting vote extension", "validator", sdk.ConsAddress(req.ValidatorAddress).String(), "error", err)
		return &abci.ResponseVerifyVoteExtension{Status: abci.ResponseVerifyVoteExtension_REJECT}, nil
	}
	return &abci.ResponseVerifyVoteExtension{Status: abci.ResponseVerifyVoteExtension_ACCEPT}, nil
}

// validateVoteExtension accepts an empty extension (a validator without a
// Bitcoin view) or a well-formed BtcBlockVoteExtension.
func validateVoteExtension(bz []byte) error {
	if len(bz) == 0 {
		return nil
	}
	if len(bz) > types.MaxVoteExtensionSize {
		return fmt.Errorf("vote extension is %d bytes, maximum is %d", len(bz), types.MaxVoteExtensionSize)
	}
	var ext types.BtcBlockVoteExtension
	if err := ext.Unmarshal(bz); err != nil {
		return err
	}
	return ext.ValidateFormat()
}
