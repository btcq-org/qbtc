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
	sdkCtx := sdk.UnwrapSDKContext(ctx)
	lastProcessedBlock, err := h.keeper.LastProcessedBlock.Get(sdkCtx)
	if err != nil {
		sdkCtx.Logger().Error("Failed to get last processed block", "error", err)
		lastProcessedBlock = 0
	}
	sdkCtx.Logger().Info("Preparing proposal", "lastProcessedBlock", lastProcessedBlock)
	// let's only fill half of the block with ebifrost inject txs, so that we leave room for normal txs
	maxTxBytes := req.MaxTxBytes / 2
	injectTxs, txBzLen := h.bifrost.ProposalInjectTxs(ctx, maxTxBytes, lastProcessedBlock)

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

func (h *ProposalHandler) ProcessProposal(ctx sdk.Context, req *abci.RequestProcessProposal) (*abci.ResponseProcessProposal, error) {
	txs := make([]sdk.Tx, 0, len(req.Txs))
	for _, bz := range req.Txs {
		tx, err := h.decoder(bz)
		if err != nil {
			return nil, err
		}
		txs = append(txs, tx)
	}

	lastProcessedBlock, err := h.keeper.GetLastProcessedBlock(ctx)
	if err != nil {
		return nil, err
	}
	if err := checkInjectedBlocks(lastProcessedBlock, txs); err != nil {
		ctx.Logger().Error("rejecting proposal", "error", err)
		return &abci.ResponseProcessProposal{Status: abci.ResponseProcessProposal_REJECT}, nil
	}

	return h.processProposalHandler(ctx, req)
}

// checkInjectedBlocks rejects a proposal that carries a top-level MsgBtcBlock
// outside a proposer-injected transaction, or injected blocks whose heights do
// not run consecutively from lastProcessedBlock+1 (from the first block's
// height when no block has been processed yet, as in PrepareProposal). The
// block handler also binds each block's content to its height; this check
// rejects a bad proposal before it is executed.
func checkInjectedBlocks(lastProcessedBlock uint64, txs []sdk.Tx) error {
	next := lastProcessedBlock + 1
	anyStart := lastProcessedBlock == 0
	for _, tx := range txs {
		injected := ebifrost.IsInjectTx(tx)
		for _, msg := range tx.GetMsgs() {
			block, ok := msg.(*types.MsgBtcBlock)
			if !ok {
				continue
			}
			if !injected {
				return fmt.Errorf("MsgBtcBlock at height %d is not in an inject transaction", block.Height)
			}
			if anyStart {
				next = block.Height
				anyStart = false
			}
			if block.Height != next {
				return fmt.Errorf("injected block height %d, expected %d", block.Height, next)
			}
			next++
		}
	}
	return nil
}
