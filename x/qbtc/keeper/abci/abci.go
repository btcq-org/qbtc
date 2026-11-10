package abci

import (
	"context"
	"fmt"

	"github.com/btcq-org/qbtc/constants"
	"github.com/btcq-org/qbtc/x/qbtc/btcreader"
	"github.com/btcq-org/qbtc/x/qbtc/keeper"
	"github.com/btcq-org/qbtc/x/qbtc/types"
	abci "github.com/cometbft/cometbft/abci/types"
	cmttypes "github.com/cometbft/cometbft/types"
	"github.com/cosmos/cosmos-sdk/baseapp"
	sdk "github.com/cosmos/cosmos-sdk/types"
)

type ProposalHandler struct {
	keeper  *keeper.Keeper
	reader  *btcreader.Reader
	decoder sdk.TxDecoder

	prepareProposalHandler sdk.PrepareProposalHandler
	processProposalHandler sdk.ProcessProposalHandler
}

func NewProposalHandler(
	k *keeper.Keeper,
	b *btcreader.Reader,
	decoder sdk.TxDecoder,
	nextPrepareProposalHandler sdk.PrepareProposalHandler,
	nextProcessProposalHandler sdk.ProcessProposalHandler,
) *ProposalHandler {

	return &ProposalHandler{
		keeper:                 k,
		reader:                 b,
		decoder:                decoder,
		prepareProposalHandler: nextPrepareProposalHandler,
		processProposalHandler: nextProcessProposalHandler,
	}
}

func (h *ProposalHandler) PrepareProposal(ctx sdk.Context, req *abci.RequestPrepareProposal) (*abci.ResponsePrepareProposal, error) {
	// let's only fill half of the block with injected MsgBtcBlock txs, so that we leave room for normal txs
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
	resp.Txs = h.withinBlockLimits(ctx, resp.Txs)

	// Combine the injected MsgBtcBlock txs with the ones selected by default handler, up to tx limit
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
		Signer:             types.BtcBlockSignerAddress,
	}
	var txBz []byte
	var txBzLen int64
	for height := lastProcessedBlock + 1; len(msg.Blocks) < types.MaxBtcBlocksPerMsg; height++ {
		voted, ok := votedBlock(ctx, req.LocalLastCommit, height)
		if !ok {
			break
		}
		cached, ok := h.reader.CachedBlock(height)
		if !ok || cached.Hash != voted.Hash || cached.CommitHash != voted.CommitHash {
			ctx.Logger().Info("btc block has a supermajority but is not in the local cache", "height", height, "hash", voted.Hash)
			break
		}
		msg.Blocks = append(msg.Blocks, &types.BtcBlock{Height: height, Hash: cached.Hash, BlockContent: cached.Content})

		bz, err := h.reader.MarshalTx(msg)
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
		bz, err := h.reader.MarshalTx(mutated)
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
	if err := h.checkBlockLimits(ctx, txs); err != nil {
		ctx.Logger().Error("rejecting proposal", "error", err)
		return &abci.ResponseProcessProposal{Status: abci.ResponseProcessProposal_REJECT}, nil
	}

	return h.processProposalHandler(ctx, req)
}

// blockLimits tracks a proposal against the per-block claim cap
// (MaxClaimsPerBlock MsgClaimWithProof messages, each a PLONK verification)
// and the consensus max_gas. With qbtc's no-op app mempool the SDK's
// ProcessProposal accepts any proposal, so without these checks a proposer
// could fill a block with claims or exceed max_gas.
type blockLimits struct {
	maxClaims int64
	maxGas    int64
	claims    int64
	gas       uint64
}

func (h *ProposalHandler) newBlockLimits(ctx sdk.Context) *blockLimits {
	l := &blockLimits{maxClaims: h.keeper.GetConfig(ctx, constants.MaxClaimsPerBlock), maxGas: -1}
	if b := ctx.ConsensusParams().Block; b != nil {
		l.maxGas = b.MaxGas
	}
	return l
}

// add counts tx against the limits and reports whether it still fits.
// Injected transactions count against neither.
func (l *blockLimits) add(tx sdk.Tx) error {
	if btcreader.IsInjectTx(tx) {
		return nil
	}
	claims := l.claims + int64(types.CountClaimMsgs(tx.GetMsgs()))
	if claims > l.maxClaims {
		return fmt.Errorf("more than %d claim messages in the block", l.maxClaims)
	}
	// As in CometBFT, max_gas -1 is the only "no limit". l.gas never exceeds
	// max_gas, so the subtraction cannot wrap, and a huge declared gas cannot
	// wrap the sum.
	gas := txGas(tx)
	if l.maxGas >= 0 && gas > uint64(l.maxGas)-l.gas {
		return fmt.Errorf("transactions want more than the block's max gas %d", l.maxGas)
	}
	l.claims, l.gas = claims, l.gas+gas
	return nil
}

// txGas is the gas tx counts against max_gas: its declared gas limit, clamped
// with types.FreeClaimGasLimit for a free claim transaction, which runs with
// that limit.
func txGas(tx sdk.Tx) uint64 {
	gasTx, ok := tx.(sdk.GasTx)
	if !ok {
		return 0
	}
	if types.IsClaimOnlyTx(tx) {
		return types.FreeClaimGasLimit(gasTx.GetGas())
	}
	return gasTx.GetGas()
}

// NewTxSelector returns the SDK's default transaction selector, counting each
// transaction at txGas, as the proposal checks do. Set it on the SDK's
// DefaultProposalHandler, whose selection runs before PrepareProposal's own
// limits. The SDK counts a transaction's declared gas, but a free claim runs
// with its declared gas clamped to types.FreeClaimMaxGas, and CheckTx admits a
// claim declaring up to max_gas. Without this, a single such claim would use
// up the SDK's gas budget and leave every other transaction out of the block.
func NewTxSelector() baseapp.TxSelector {
	return txSelector{TxSelector: baseapp.NewDefaultTxSelector()}
}

type txSelector struct {
	baseapp.TxSelector
}

func (s txSelector) SelectTxForProposal(ctx context.Context, maxTxBytes, maxBlockGas uint64, memTx sdk.Tx, txBz []byte, _ uint64) bool {
	return s.TxSelector.SelectTxForProposal(ctx, maxTxBytes, maxBlockGas, memTx, txBz, txGas(memTx))
}

// withinBlockLimits drops the transactions that would take the proposal past
// the claim cap or max_gas. They stay in the mempool for a later block.
func (h *ProposalHandler) withinBlockLimits(ctx sdk.Context, txs [][]byte) [][]byte {
	limits := h.newBlockLimits(ctx)
	kept := make([][]byte, 0, len(txs))
	for _, bz := range txs {
		tx, err := h.decoder(bz)
		if err != nil {
			continue
		}
		if err := limits.add(tx); err != nil {
			ctx.Logger().Debug("leaving transaction out of the proposal", "reason", err)
			continue
		}
		kept = append(kept, bz)
	}
	return kept
}

// checkBlockLimits rejects a proposal past the claim cap or max_gas.
func (h *ProposalHandler) checkBlockLimits(ctx sdk.Context, txs []sdk.Tx) error {
	limits := h.newBlockLimits(ctx)
	for _, tx := range txs {
		if err := limits.add(tx); err != nil {
			return err
		}
	}
	return nil
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
		injected := btcreader.IsInjectTx(tx)
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
	if msg.Signer != types.BtcBlockSignerAddress {
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
