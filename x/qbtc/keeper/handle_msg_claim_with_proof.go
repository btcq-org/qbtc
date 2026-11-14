package keeper

import (
	"context"
	"fmt"

	"github.com/btcq-org/qbtc/constants"
	"github.com/btcq-org/qbtc/x/qbtc/types"
	sdk "github.com/cosmos/cosmos-sdk/types"
	sdkerror "github.com/cosmos/cosmos-sdk/types/errors"
)

// ClaimWithProof handles the MsgClaimWithProof message.
// It looks up all specified UTXOs, verifies the ZK proof against the first UTXO's address,
// and releases only the UTXOs that match the proven address.
// UTXOs with non-matching addresses are skipped (not failed) for better UX.
func (s *msgServer) ClaimWithProof(ctx context.Context, msg *types.MsgClaimWithProof) (*types.MsgClaimWithProofResponse, error) {
	sdkCtx := sdk.UnwrapSDKContext(ctx)
	if err := msg.ValidateBasic(); err != nil {
		return nil, err
	}

	claim, err := s.k.resolveClaim(sdkCtx, msg)
	if err != nil {
		return nil, err
	}
	// The ante handler verified the proof of a free claim tx. Anything else,
	// such as a claim nested in authz MsgExec, is verified here and pays for it.
	if !isVerifiedClaim(sdkCtx, claim) {
		sdkCtx.GasMeter().ConsumeGas(ClaimProofVerifyGas, "zk claim proof verification")
		if err := verifyClaimProof(claim); err != nil {
			return nil, err
		}
	}
	provenBtcAddress := claim.btcAddress
	recipientAddr := claim.recipient
	recipientBech32 := claim.recipientBech32

	minConfirmations := s.k.GetConfig(sdkCtx, constants.MinUtxoConfirmationBlocks)
	lastProcessedBlock, err := s.k.GetLastProcessedBlock(sdkCtx)
	if err != nil {
		return nil, sdkerror.ErrUnknownRequest.Wrapf("failed to get last processed block: %v", err)
	}

	// Collect UTXOs that match the proven address
	type claimableUTXO struct {
		index  int
		txid   string
		vout   uint32
		amount uint64
	}
	var claimableUTXOs []claimableUTXO
	var skippedCount uint32

	for i, utxoRef := range msg.Utxos {
		utxoKey := getUTXOKey(utxoRef.Txid, utxoRef.Vout)
		utxo, err := s.k.Utxoes.Get(sdkCtx, utxoKey)
		if err != nil {
			skippedCount++
			sdkCtx.Logger().Debug("skipping UTXO: not found",
				"index", i, "txid", utxoRef.Txid, "vout", utxoRef.Vout)
			continue
		}

		if utxo.EntitledAmount == 0 {
			skippedCount++
			sdkCtx.Logger().Debug("skipping UTXO: already claimed",
				"index", i, "txid", utxoRef.Txid, "vout", utxoRef.Vout)
			continue
		}

		if utxo.ScriptPubKey == nil || utxo.ScriptPubKey.Address == "" {
			skippedCount++
			sdkCtx.Logger().Debug("skipping UTXO: no address",
				"index", i, "txid", utxoRef.Txid, "vout", utxoRef.Vout)
			continue
		}

		if minConfirmations > 0 && utxo.BlockHeight > 0 && lastProcessedBlock < utxo.BlockHeight+uint64(minConfirmations) {
			skippedCount++
			sdkCtx.Logger().Debug("skipping UTXO: not enough confirmations",
				"index", i, "txid", utxoRef.Txid, "vout", utxoRef.Vout,
				"utxo_block_height", utxo.BlockHeight,
				"last_processed_block", lastProcessedBlock,
				"min_confirmations", minConfirmations,
			)
			continue
		}

		// The signature covers this exact address string, so the same key's
		// UTXOs at its other address type are not part of this claim.
		if utxo.ScriptPubKey.Address != provenBtcAddress {
			skippedCount++
			sdkCtx.Logger().Debug("skipping UTXO: address mismatch",
				"index", i,
				"txid", utxoRef.Txid,
				"vout", utxoRef.Vout,
				"expected", provenBtcAddress,
				"got", utxo.ScriptPubKey.Address,
			)
			continue
		}

		// This UTXO matches - add to claimable list
		claimableUTXOs = append(claimableUTXOs, claimableUTXO{
			index:  i,
			txid:   utxoRef.Txid,
			vout:   utxoRef.Vout,
			amount: utxo.EntitledAmount,
		})
	}

	if len(claimableUTXOs) == 0 {
		return nil, sdkerror.ErrInvalidRequest.Wrap("no UTXOs match the proven address")
	}

	// Use cache context for atomic batch claim
	cacheCtx, write := sdkCtx.CacheContext()

	var totalClaimed uint64
	for _, utxo := range claimableUTXOs {
		if err := s.k.ClaimUTXO(cacheCtx, utxo.txid, utxo.vout, recipientAddr, msg.Referrer); err != nil {
			return nil, sdkerror.ErrInvalidRequest.Wrapf("failed to claim UTXO[%d]: %v", utxo.index, err)
		}
		totalClaimed += utxo.amount
	}

	// Commit all claims atomically
	write()

	if claim.referrer != nil {
		s.k.applyReferral(sdkCtx, claim.referrer, recipientAddr, totalClaimed)
	}

	// Emit batch event
	sdkCtx.EventManager().EmitEvent(
		sdk.NewEvent(
			"claim_with_proof",
			sdk.NewAttribute("claimer", msg.Claimer),
			sdk.NewAttribute("receiver", recipientBech32),
			sdk.NewAttribute("referrer", msg.Referrer),
			sdk.NewAttribute("btc_address", provenBtcAddress),
			sdk.NewAttribute("utxos_claimed", fmt.Sprintf("%d", len(claimableUTXOs))),
			sdk.NewAttribute("utxos_skipped", fmt.Sprintf("%d", skippedCount)),
			sdk.NewAttribute("total_amount", fmt.Sprintf("%d", totalClaimed)),
		),
	)

	sdkCtx.Logger().Info("batch claimed with proof",
		"claimer", msg.Claimer,
		"receiver", recipientBech32,
		"referrer", msg.Referrer,
		"btc_address", provenBtcAddress,
		"utxos_claimed", len(claimableUTXOs),
		"utxos_skipped", skippedCount,
		"total_amount", totalClaimed,
	)

	return &types.MsgClaimWithProofResponse{
		TotalAmountClaimed: totalClaimed,
		UtxosClaimed:       uint32(len(claimableUTXOs)),
		UtxosSkipped:       skippedCount,
	}, nil
}
