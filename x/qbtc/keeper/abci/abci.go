package abci

import (
	"bytes"

	"github.com/btcq-org/qbtc/x/qbtc/ebifrost"
	"github.com/btcq-org/qbtc/x/qbtc/keeper"
	"github.com/btcq-org/qbtc/x/qbtc/types"
	abci "github.com/cometbft/cometbft/abci/types"
	cmttypes "github.com/cometbft/cometbft/types"
	sdk "github.com/cosmos/cosmos-sdk/types"
)

const (
	// maxAttestItems caps how many Bitcoin block digests a single vote extension
	// may attest, bounding precommit size.
	maxAttestItems = 16
	// maxVoteExtBytes caps the accepted vote-extension size.
	maxVoteExtBytes = 64 * 1024
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

func (h *ProposalHandler) lastProcessed(ctx sdk.Context) uint64 {
	lastProcessed, err := h.keeper.LastProcessedBlock.Get(ctx)
	if err != nil {
		return 0
	}
	return lastProcessed
}

// ExtendVote attaches digests of the Bitcoin blocks this validator has observed
// and is ready to attest. It carries only (height, block hash, delta hash) — the
// precommit signature CometBFT produces over the extension is the attestation.
func (h *ProposalHandler) ExtendVote(ctx sdk.Context, _ *abci.RequestExtendVote) (*abci.ResponseExtendVote, error) {
	lastProcessed := h.lastProcessed(ctx)
	// Publish the chain's last-processed height so the embedded observer fetches
	// the blocks above it (and prunes those already applied).
	h.bifrost.SetFloor(lastProcessed)

	ve := &types.BtcBlockVoteExtension{Items: h.bifrost.ObservedAttests(lastProcessed, maxAttestItems)}
	bz, err := ve.Marshal()
	if err != nil {
		return nil, err
	}
	return &abci.ResponseExtendVote{VoteExtension: bz}, nil
}

// VerifyVoteExtension is intentionally tolerant: it rejects only malformed or
// abusive extensions, never an honest peer whose Bitcoin view merely differs
// from ours, since that would stall consensus.
func (h *ProposalHandler) VerifyVoteExtension(_ sdk.Context, req *abci.RequestVerifyVoteExtension) (*abci.ResponseVerifyVoteExtension, error) {
	accept := &abci.ResponseVerifyVoteExtension{Status: abci.ResponseVerifyVoteExtension_ACCEPT}
	reject := &abci.ResponseVerifyVoteExtension{Status: abci.ResponseVerifyVoteExtension_REJECT}

	if len(req.VoteExtension) == 0 {
		return accept, nil // a validator with no Bitcoin view is allowed
	}
	if len(req.VoteExtension) > maxVoteExtBytes {
		return reject, nil
	}
	var ve types.BtcBlockVoteExtension
	if err := ve.Unmarshal(req.VoteExtension); err != nil {
		return reject, nil
	}
	if len(ve.Items) > maxAttestItems {
		return reject, nil
	}
	seen := make(map[uint64]bool, len(ve.Items))
	for _, item := range ve.Items {
		if len(item.BlockHash) == 0 || len(item.DeltaHash) != 32 {
			return reject, nil
		}
		if seen[item.Height] {
			return reject, nil // duplicate height in one extension
		}
		seen[item.Height] = true
	}
	return accept, nil
}

// PrepareProposal injects the next contiguous Bitcoin block delta when a >2/3
// supermajority attested its digest in the previous height's vote extensions.
// The full delta bytes come from this proposer's own cache; the proof of
// supermajority is the embedded ExtendedCommitInfo.
func (h *ProposalHandler) PrepareProposal(ctx sdk.Context, req *abci.RequestPrepareProposal) (*abci.ResponsePrepareProposal, error) {
	target := h.lastProcessed(ctx) + 1

	var injectTxs [][]byte
	var injectedSize int64

	blockHash, deltaHash, power, total := keeper.TallyBtcBlockDelta(req.LocalLastCommit, target)
	if total > 0 && power*3 > total*2 {
		if d, digest, ok := h.bifrost.GetDelta(target); ok &&
			bytes.Equal(digest, deltaHash) && bytes.Equal(d.BlockHash, blockHash) {
			if extBz, err := req.LocalLastCommit.Marshal(); err == nil {
				msg := &types.MsgInjectBtcBlock{
					Delta:              d,
					ExtendedCommitInfo: extBz,
					Signer:             ebifrost.SignerAcc,
				}
				if txBz, err := h.bifrost.MarshalTx(msg); err == nil {
					sz := cmttypes.ComputeProtoSizeForTxs([]cmttypes.Tx{txBz})
					if sz <= req.MaxTxBytes/2 {
						injectTxs = append(injectTxs, txBz)
						injectedSize = sz
					}
				} else {
					ctx.Logger().Error("failed to marshal injected btc block", "error", err)
				}
			}
		} else {
			ctx.Logger().Info("supermajority reached but proposer lacks matching delta bytes", "height", target)
		}
	}

	// Reserve room for the injected tx, then let the default handler fill the rest.
	origMaxTxBytes := req.MaxTxBytes
	if injectedSize >= req.MaxTxBytes {
		req.MaxTxBytes = 0
	} else {
		req.MaxTxBytes -= injectedSize
	}

	resp, err := h.prepareProposalHandler(ctx, req)
	if err != nil {
		return nil, err
	}

	combinedTxs := injectTxs
	totalSize := injectedSize
	for _, tx := range resp.Txs {
		txSize := cmttypes.ComputeProtoSizeForTxs([]cmttypes.Tx{tx})
		if totalSize+txSize <= origMaxTxBytes {
			totalSize += txSize
			combinedTxs = append(combinedTxs, tx)
		}
	}
	return &abci.ResponsePrepareProposal{Txs: combinedTxs}, nil
}

// ProcessProposal independently re-validates any injected Bitcoin block: it must
// be the first tx and must carry a valid >2/3 vote-extension supermajority over
// the delta digest. This is the consensus safety boundary.
func (h *ProposalHandler) ProcessProposal(ctx sdk.Context, req *abci.RequestProcessProposal) (*abci.ResponseProcessProposal, error) {
	reject := &abci.ResponseProcessProposal{Status: abci.ResponseProcessProposal_REJECT}

	for i, bz := range req.Txs {
		tx, err := h.decoder(bz)
		if err != nil {
			return reject, nil
		}
		msgs := tx.GetMsgs()
		hasInject := false
		for _, msg := range msgs {
			if _, ok := msg.(*types.MsgInjectBtcBlock); ok {
				hasInject = true
				break
			}
		}
		if !hasInject {
			continue
		}
		// The envelope must be exactly what InjectedTxDecorator.AnteHandle
		// accepts at delivery (the inject wrapper, first tx, single allowed
		// message). Otherwise the proposal could pass here and then silently
		// drop the BTC delta during FinalizeBlock.
		if i != 0 || !ebifrost.IsInjectTx(tx) || len(msgs) != 1 {
			ctx.Logger().Error("reject proposal: malformed injected btc block envelope", "index", i)
			return reject, nil
		}
		inj := msgs[0].(*types.MsgInjectBtcBlock)
		if err := h.keeper.ValidateInjectedBtcBlock(ctx, inj); err != nil {
			ctx.Logger().Error("reject proposal: invalid injected btc block", "error", err)
			return reject, nil
		}
	}

	return h.processProposalHandler(ctx, req)
}
