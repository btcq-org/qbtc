package abci

import (
	"fmt"

	"github.com/btcq-org/qbtc/x/qbtc/ebifrost"
	"github.com/btcq-org/qbtc/x/qbtc/keeper"
	"github.com/btcq-org/qbtc/x/qbtc/types"
	abci "github.com/cometbft/cometbft/abci/types"
	cmttypes "github.com/cometbft/cometbft/types"
	sdk "github.com/cosmos/cosmos-sdk/types"
)

type ProposalHandler struct {
	keeper  *keeper.Keeper
	bifrost *ebifrost.EnshrinedBifrost
	decoder sdk.TxDecoder

	prepareProposalHandler sdk.PrepareProposalHandler
	processProposalHandler sdk.ProcessProposalHandler
}

func NewProposalHandler(
	k *keeper.Keeper,
	b *ebifrost.EnshrinedBifrost,
	decoder sdk.TxDecoder,
	nextPrepareProposalHandler sdk.PrepareProposalHandler,
	nextProcessProposalHandler sdk.ProcessProposalHandler,
) *ProposalHandler {

	return &ProposalHandler{
		keeper:                 k,
		bifrost:                b,
		decoder:                decoder,
		prepareProposalHandler: nextPrepareProposalHandler,
		processProposalHandler: nextProcessProposalHandler,
	}
}

func (h *ProposalHandler) PrepareProposal(ctx sdk.Context, req *abci.RequestPrepareProposal) (*abci.ResponsePrepareProposal, error) {
	// let's only fill half of the block with ebifrost inject txs, so that we leave room for normal txs
	maxTxBytes := req.MaxTxBytes / 2
	injectTxs, txBzLen := h.votedInjectTxs(ctx, req, maxTxBytes)

	// Modify request for upstream handler with reduced max tx size
	origMaxTxBytes := req.MaxTxBytes
	if txBzLen >= req.MaxTxBytes {
		req.MaxTxBytes = 0
	} else {
		req.MaxTxBytes -= txBzLen
	}

	// Let default handler process original txs with reduced size
	resp, err := h.prepareProposalHandler(ctx, req)
	if err != nil {
		return nil, err
	}

	// Combine ebifrost inject txs with the ones selected by default handler, up to tx limit
	combinedTxs := injectTxs

	defaultTxsSize := int64(0)
	totalSize := txBzLen
	for _, tx := range resp.Txs {
		txSize := cmttypes.ComputeProtoSizeForTxs([]cmttypes.Tx{tx})
		defaultTxsSize += txSize
		if totalSize+txSize <= origMaxTxBytes {
			totalSize += txSize
			combinedTxs = append(combinedTxs, tx)
		} else {
			ctx.Logger().Warn(
				"Dropping transaction that would exceed block size limit",
				"current_size", totalSize,
				"tx_size", txSize,
				"max_size", origMaxTxBytes,
			)
		}
	}

	ctx.Logger().Info(
		"Proposal Transaction sizes",
		"injected_txs_count", len(injectTxs),
		"injected_txs_size", txBzLen,
		"default_txs_count", len(resp.Txs),
		"default_txs_size", defaultTxsSize,
		"final_txs_size", totalSize,
		"final_txs_count", len(combinedTxs),
		"max_bytes", req.MaxTxBytes,
		"original_max_bytes", origMaxTxBytes,
	)

	return &abci.ResponsePrepareProposal{Txs: combinedTxs}, nil
}

// votedInjectTxs returns the inject transaction for the consecutive Bitcoin
// blocks, from the next unprocessed height, that validators with more than 2/3
// of the voting power attested in the previous block's vote extensions and
// that this node has cached, along with its length in the proposal. It returns
// nothing if no block qualifies. The blocks go in one MsgBtcBlock, with the
// extended commit once.
func (h *ProposalHandler) votedInjectTxs(ctx sdk.Context, req *abci.RequestPrepareProposal, maxTxBytes int64) ([][]byte, int64) {
	if !keeper.VoteExtensionsEnabled(ctx) {
		return nil, 0
	}
	lastProcessedBlock, err := h.keeper.GetLastProcessedBlock(ctx)
	if err != nil {
		ctx.Logger().Error("failed to get last processed block", "error", err)
		return nil, 0
	}
	extendedCommit, err := req.LocalLastCommit.Marshal()
	if err != nil {
		ctx.Logger().Error("failed to marshal the extended commit", "error", err)
		return nil, 0
	}

	msg := &types.MsgBtcBlock{
		ExtendedCommitInfo: extendedCommit,
		Signer:             types.EBifrostSignerAddress,
	}
	var txBz []byte
	var txBzLen int64
	for height := lastProcessedBlock + 1; len(msg.Blocks) < types.MaxBtcBlockVotes; height++ {
		voted, ok := votedBlock(ctx, req.LocalLastCommit, height)
		if !ok {
			break
		}
		cached, ok := h.bifrost.CachedBlock(height)
		if !ok || cached.Hash != voted.Hash || cached.CommitHash != voted.CommitHash {
			ctx.Logger().Info("btc block has a supermajority but is not in the local cache", "height", height, "hash", voted.Hash)
			break
		}
		msg.Blocks = append(msg.Blocks, &types.BtcBlock{Height: height, Hash: cached.Hash, BlockContent: cached.Content})

		bz, err := h.bifrost.MarshalTx(msg)
		if err != nil {
			ctx.Logger().Error("failed to marshal the inject tx", "error", err)
			return nil, 0
		}
		size := cmttypes.ComputeProtoSizeForTxs([]cmttypes.Tx{bz})
		if size > maxTxBytes {
			msg.Blocks = msg.Blocks[:len(msg.Blocks)-1]
			break
		}
		txBz, txBzLen = bz, size
	}
	if len(msg.Blocks) == 0 {
		return nil, 0
	}

	// Check what the other validators will check, so that a proposal this node
	// builds is not rejected for its evidence.
	if err := h.keeper.ValidateBtcBlockVotes(ctx, msg); err != nil {
		ctx.Logger().Error("not injecting btc blocks, their votes are invalid", "error", err)
		return nil, 0
	}

	if mutated := mutateInjectedMsg(ctx, msg); mutated != msg {
		bz, err := h.bifrost.MarshalTx(mutated)
		if err != nil {
			ctx.Logger().Error("failed to marshal the inject tx", "error", err)
			return nil, 0
		}
		txBz, txBzLen = bz, cmttypes.ComputeProtoSizeForTxs([]cmttypes.Tx{bz})
	}

	first, last := msg.Blocks[0], msg.Blocks[len(msg.Blocks)-1]
	ctx.Logger().Info("injecting btc blocks",
		"from", first.Height,
		"to", last.Height,
		"count", len(msg.Blocks),
		"tx_bytes", txBzLen,
		"extended_commit_bytes", len(extendedCommit),
	)
	return [][]byte{txBz}, txBzLen
}

// votedBlock returns what validators with more than 2/3 of the voting power
// attested for the Bitcoin height in the extended commit, if anything.
func votedBlock(ctx sdk.Context, extendedCommit abci.ExtendedCommitInfo, height uint64) (keeper.BtcVoteKey, bool) {
	power, total := keeper.TallyBtcBlockVotes(extendedCommit, height)
	var voted keeper.BtcVoteKey
	found := false
	for key, p := range power {
		ctx.Logger().Info("btc vote tally", "btc_height", height, "hash", key.Hash, "power", p, "total", total)
		// more than 2/3 of the power is unique to one key
		if keeper.HasSupermajority(p, total) {
			voted, found = key, true
		}
	}
	return voted, found
}

func (h *ProposalHandler) ProcessProposal(ctx sdk.Context, req *abci.RequestProcessProposal) (*abci.ResponseProcessProposal, error) {
	txs := make([]sdk.Tx, 0, len(req.Txs))
	for _, bz := range req.Txs {
		tx, err := h.decoder(bz)
		if err != nil {
			return nil, err
		}
		txs = append(txs, tx)
	}

	if err := h.checkInjectedBlocks(ctx, txs); err != nil {
		ctx.Logger().Error("rejecting proposal", "error", err)
		return &abci.ResponseProcessProposal{Status: abci.ResponseProcessProposal_REJECT}, nil
	}

	return h.processProposalHandler(ctx, req)
}

// checkInjectedBlocks rejects a proposal that carries a MsgBtcBlock outside a
// proposer-injected transaction, more than one MsgBtcBlock, or one that vote
// extensions do not back: it needs vote extensions to be enabled, the signer of
// injected messages, blocks at consecutive heights from the next unprocessed
// one, and the extended commit with valid signatures and more than 2/3 of the
// voting power behind every block. The block handler repeats these checks and
// verifies the blocks themselves; checking here rejects a bad proposal before
// it is executed.
func (h *ProposalHandler) checkInjectedBlocks(ctx sdk.Context, txs []sdk.Tx) error {
	var msg *types.MsgBtcBlock
	for _, tx := range txs {
		injected := ebifrost.IsInjectTx(tx)
		for _, m := range tx.GetMsgs() {
			block, ok := m.(*types.MsgBtcBlock)
			if !ok {
				continue
			}
			if !injected {
				return fmt.Errorf("MsgBtcBlock is not in an inject transaction")
			}
			if msg != nil {
				return fmt.Errorf("more than one MsgBtcBlock in the proposal")
			}
			msg = block
		}
	}
	if msg == nil {
		return nil
	}

	if !keeper.VoteExtensionsEnabled(ctx) {
		return fmt.Errorf("MsgBtcBlock needs vote extensions, which are not enabled at height %d", ctx.HeaderInfo().Height)
	}
	if msg.Signer != types.EBifrostSignerAddress {
		return fmt.Errorf("MsgBtcBlock signer %s is not the injection signer", msg.Signer)
	}
	if err := msg.ValidateBasic(); err != nil {
		return err
	}
	lastProcessedBlock, err := h.keeper.GetLastProcessedBlock(ctx)
	if err != nil {
		return err
	}
	if err := checkBlockHeights(lastProcessedBlock, msg.Blocks); err != nil {
		return err
	}
	return h.keeper.ValidateBtcBlockVotes(ctx, msg)
}

// checkBlockHeights checks that blocks run consecutively from
// lastProcessedBlock+1. The block handler also checks it, and binds each
// block's content to its height.
func checkBlockHeights(lastProcessedBlock uint64, blocks []*types.BtcBlock) error {
	next := lastProcessedBlock + 1
	for _, block := range blocks {
		if block.Height != next {
			return fmt.Errorf("injected block height %d, expected %d", block.Height, next)
		}
		next++
	}
	return nil
}
