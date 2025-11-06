package abci

import (
	"github.com/btcq-org/qbtc/x/qbtc/ebifrost"
	"github.com/btcq-org/qbtc/x/qbtc/keeper"
	abci "github.com/cometbft/cometbft/abci/types"
	cmttypes "github.com/cometbft/cometbft/types"
	"github.com/cosmos/cosmos-sdk/codec"
	codectypes "github.com/cosmos/cosmos-sdk/codec/types"
	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/cosmos/cosmos-sdk/x/auth/tx"
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
	r codectypes.InterfaceRegistry,
	nextPrepareProposalHandler sdk.PrepareProposalHandler,
	nextProcessProposalHandler sdk.ProcessProposalHandler,
) *ProposalHandler {
	cdc := codec.NewProtoCodec(r)
	decoder := ebifrost.TxDecoder(cdc, tx.DefaultTxDecoder(cdc))

	return &ProposalHandler{
		keeper:                 k,
		bifrost:                b,
		decoder:                decoder,
		prepareProposalHandler: nextPrepareProposalHandler,
		processProposalHandler: nextProcessProposalHandler,
	}
}

func (h *ProposalHandler) PrepareProposal(ctx sdk.Context, req *abci.RequestPrepareProposal) (*abci.ResponsePrepareProposal, error) {
	injectTxs, txBzLen := h.bifrost.ProposalInjectTxs(ctx, req.MaxTxBytes)

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
	for _, bz := range req.Txs {
		_, err := h.decoder(bz)
		if err != nil {
			return nil, err
		}
	}

	return h.processProposalHandler(ctx, req)
}
