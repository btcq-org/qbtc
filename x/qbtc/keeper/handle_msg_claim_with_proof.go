package keeper

import (
	"context"
	"encoding/hex"
	"fmt"

	"github.com/btcq-org/qbtc/constants"
	"github.com/btcq-org/qbtc/x/qbtc/types"
	"github.com/btcq-org/qbtc/x/qbtc/zk"
	sdk "github.com/cosmos/cosmos-sdk/types"
	sdkerror "github.com/cosmos/cosmos-sdk/types/errors"
)

// ClaimWithProof handles the MsgClaimWithProof message.
// It looks up all specified UTXOs, verifies the ZK proof against the first UTXO's address,
// and releases only the UTXOs that match the proven address.
// UTXOs with non-matching addresses are skipped (not failed) for better UX.
func (s *msgServer) ClaimWithProof(ctx context.Context, msg *types.MsgClaimWithProof) (*types.MsgClaimWithProofResponse, error) {
	sdkCtx := sdk.UnwrapSDKContext(ctx)
	isDisabled := s.k.GetConfig(sdkCtx, constants.ClaimWithProofDisabled)
	if isDisabled > 0 {
		return nil, sdkerror.ErrInvalidRequest.Wrap("ClaimWithProof feature is disabled")
	}

	// Validate the message
	if err := msg.ValidateBasic(); err != nil {
		return nil, err
	}

	// Ensure the ZK verifier is initialized
	if !zk.IsVerifierInitialized() {
		return nil, sdkerror.ErrInvalidRequest.Wrap("ZK verifier not initialized")
	}

	minConfirmations := s.k.GetConfig(sdkCtx, constants.MinUtxoConfirmationBlocks)
	lastProcessedBlock, err := s.k.GetLastProcessedBlock(sdkCtx)
	if err != nil {
		return nil, sdkerror.ErrUnknownRequest.Wrapf("failed to get last processed block: %v", err)
	}

	// Parse the claimer address upfront
	claimerAddr, err := sdk.AccAddressFromBech32(msg.Claimer)
	if err != nil {
		return nil, sdkerror.ErrInvalidAddress.Wrapf("invalid claimer address: %v", err)
	}

	// Resolve the destination: receiver overrides claimer when set
	recipientAddr := claimerAddr
	recipientBech32 := msg.Claimer
	if msg.Receiver != "" {
		receiverAddr, err := sdk.AccAddressFromBech32(msg.Receiver)
		if err != nil {
			return nil, sdkerror.ErrInvalidAddress.Wrapf("invalid receiver address: %v", err)
		}
		recipientAddr = receiverAddr
		recipientBech32 = msg.Receiver
	}

	// The optional referrer; ValidateBasic has checked it is canonical and not
	// the destination.
	var referrerAddr sdk.AccAddress
	if msg.Referrer != "" {
		referrerAddr, err = sdk.AccAddressFromBech32(msg.Referrer)
		if err != nil {
			return nil, sdkerror.ErrInvalidAddress.Wrapf("invalid referrer address: %v", err)
		}
	}

	// Find the first valid UTXO to determine the proven address
	var provenBtcAddress string
	var foundValidUtxo bool

	for i, utxoRef := range msg.Utxos {
		utxoKey := getUTXOKey(utxoRef.Txid, utxoRef.Vout)
		utxo, err := s.k.Utxoes.Get(sdkCtx, utxoKey)
		if err != nil {
			continue // Skip non-existent UTXOs
		}

		if utxo.EntitledAmount == 0 {
			continue // Skip already claimed UTXOs
		}

		if utxo.ScriptPubKey == nil || utxo.ScriptPubKey.Address == "" {
			continue // Skip UTXOs without address
		}

		if minConfirmations > 0 && utxo.BlockHeight > 0 && lastProcessedBlock < utxo.BlockHeight+uint64(minConfirmations) {
			continue // Skip UTXOs that have not reached the minimum confirmation threshold
		}

		if _, err := zk.BitcoinAddressToHash160(utxo.ScriptPubKey.Address); err != nil {
			continue // Skip UTXOs with invalid addresses
		}

		// Found a valid UTXO - use its address for proof verification
		provenBtcAddress = utxo.ScriptPubKey.Address
		foundValidUtxo = true
		sdkCtx.Logger().Debug("using UTXO for proof verification",
			"index", i,
			"txid", utxoRef.Txid,
			"vout", utxoRef.Vout,
			"btc_address", provenBtcAddress,
		)
		break
	}

	if !foundValidUtxo {
		return nil, sdkerror.ErrInvalidRequest.Wrap("no valid claimable UTXOs found")
	}

	// Verify the ZK proof against the determined address. The signed claim
	// message names recipientBech32 as destination (receiver when set, claimer
	// otherwise) and msg.Referrer as referrer, so the proof binds to where the
	// coins actually go and to who referred the claim.
	if err := s.verifyProof(sdkCtx, msg, provenBtcAddress, recipientBech32); err != nil {
		return nil, sdkerror.ErrInvalidRequest.Wrapf("proof verification failed: %v", err)
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

	if referrerAddr != nil {
		s.k.applyReferral(sdkCtx, referrerAddr, recipientAddr, totalClaimed)
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

// verifyProof verifies the ZK proof for the claim. provenBtcAddress is the
// address string stored on the UTXO being claimed and recipientBech32 is the
// address the proof must commit to: the receiver when set, otherwise the
// claimer. Both, and the optional referrer, are part of the signed claim
// message, which prevents front-running, redirection and referrer swaps.
func (s *msgServer) verifyProof(sdkCtx sdk.Context, msg *types.MsgClaimWithProof, provenBtcAddress, recipientBech32 string) error {
	proofBytes, err := hex.DecodeString(msg.Proof)
	if err != nil {
		return fmt.Errorf("proof data is not valid hex: %w", err)
	}

	// The claimer supplies SHA256 of their SEC-compressed pubkey; the verifier
	// natively checks RIPEMD160 of it matches the UTXO's address. ValidateBasic
	// has already enforced the hex/length shape.
	pubKeyHashBytes, err := hex.DecodeString(msg.PubKeyHashSha256)
	if err != nil {
		return fmt.Errorf("pub_key_hash_sha256 is not valid hex: %w", err)
	}
	var pubKeyHashSHA256 [32]byte
	copy(pubKeyHashSHA256[:], pubKeyHashBytes)

	return zk.VerifyProofGlobal(proofBytes, zk.VerificationParams{
		ChainID:          sdkCtx.ChainID(),
		BitcoinAddress:   provenBtcAddress,
		QBTCAddress:      recipientBech32,
		Referrer:         msg.Referrer,
		PubKeyHashSHA256: pubKeyHashSHA256,
	})
}
