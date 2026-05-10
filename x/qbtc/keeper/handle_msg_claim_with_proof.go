package keeper

import (
	"bytes"
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
	if err := msg.ValidateBasic(); err != nil {
		return nil, err
	}

	if !zk.IsVerifierInitialized() {
		return nil, sdkerror.ErrInvalidRequest.Wrap("ZK verifier not initialized")
	}

	claimerAddr, err := sdk.AccAddressFromBech32(msg.Claimer)
	if err != nil {
		return nil, sdkerror.ErrInvalidAddress.Wrapf("invalid claimer address: %v", err)
	}

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

	// Find the first valid UTXO to determine the proven address. The hash160
	// is now stored directly on the UTXO, so no per-UTXO string→hash160
	// conversion is needed at claim time.
	var provenAddressHash [20]byte
	var foundValidUtxo bool

	for i, utxoRef := range msg.Utxos {
		utxoKey := types.UTXOKey(utxoRef.Txid, utxoRef.Vout)
		utxo, err := s.k.Utxoes.Get(sdkCtx, utxoKey)
		if err != nil {
			continue
		}
		if utxo.EntitledAmount == 0 {
			continue
		}
		if len(utxo.Address) != 20 {
			continue
		}
		copy(provenAddressHash[:], utxo.Address)
		foundValidUtxo = true
		sdkCtx.Logger().Debug("using UTXO for proof verification",
			"index", i,
			"txid", hex.EncodeToString(utxoRef.Txid),
			"vout", utxoRef.Vout,
			"address_hash", hex.EncodeToString(utxo.Address),
		)
		break
	}

	if !foundValidUtxo {
		return nil, sdkerror.ErrInvalidRequest.Wrap("no valid claimable UTXOs found")
	}

	if err := s.verifyProof(sdkCtx, msg, provenAddressHash, recipientBech32); err != nil {
		return nil, sdkerror.ErrInvalidRequest.Wrapf("proof verification failed: %v", err)
	}

	type claimableUTXO struct {
		index  int
		txid   []byte
		vout   uint32
		amount uint64
	}
	var claimableUTXOs []claimableUTXO
	var skippedCount uint32

	for i, utxoRef := range msg.Utxos {
		utxoKey := types.UTXOKey(utxoRef.Txid, utxoRef.Vout)
		utxo, err := s.k.Utxoes.Get(sdkCtx, utxoKey)
		if err != nil {
			skippedCount++
			sdkCtx.Logger().Debug("skipping UTXO: not found",
				"index", i, "txid", hex.EncodeToString(utxoRef.Txid), "vout", utxoRef.Vout)
			continue
		}
		if utxo.EntitledAmount == 0 {
			skippedCount++
			continue
		}
		if len(utxo.Address) != 20 {
			skippedCount++
			continue
		}
		if !bytes.Equal(provenAddressHash[:], utxo.Address) {
			skippedCount++
			sdkCtx.Logger().Debug("skipping UTXO: address mismatch",
				"index", i,
				"txid", hex.EncodeToString(utxoRef.Txid),
				"vout", utxoRef.Vout,
				"expected", hex.EncodeToString(provenAddressHash[:]),
				"got", hex.EncodeToString(utxo.Address),
			)
			continue
		}

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

	cacheCtx, write := sdkCtx.CacheContext()

	var totalClaimed uint64
	for _, utxo := range claimableUTXOs {
		if err := s.k.ClaimUTXO(cacheCtx, utxo.txid, utxo.vout, recipientAddr); err != nil {
			return nil, sdkerror.ErrInvalidRequest.Wrapf("failed to claim UTXO[%d]: %v", utxo.index, err)
		}
		totalClaimed += utxo.amount
	}

	write()

	sdkCtx.EventManager().EmitEvent(
		sdk.NewEvent(
			"claim_with_proof",
			sdk.NewAttribute("claimer", msg.Claimer),
			sdk.NewAttribute("receiver", recipientBech32),
			sdk.NewAttribute("address_hash", hex.EncodeToString(provenAddressHash[:])),
			sdk.NewAttribute("utxos_claimed", fmt.Sprintf("%d", len(claimableUTXOs))),
			sdk.NewAttribute("utxos_skipped", fmt.Sprintf("%d", skippedCount)),
			sdk.NewAttribute("total_amount", fmt.Sprintf("%d", totalClaimed)),
		),
	)

	sdkCtx.Logger().Info("batch claimed with proof",
		"claimer", msg.Claimer,
		"receiver", recipientBech32,
		"address_hash", hex.EncodeToString(provenAddressHash[:]),
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

// verifyProof verifies the ZK proof for the claim.
// recipientBech32 is the address the proof must commit to — it is the receiver
// when set, otherwise the claimer. This binding prevents front-running.
func (s *msgServer) verifyProof(sdkCtx sdk.Context, msg *types.MsgClaimWithProof, addressHash [20]byte, recipientBech32 string) error {
	proofBytes, err := hex.DecodeString(msg.Proof)
	if err != nil {
		return fmt.Errorf("proof data is not valid hex: %w", err)
	}

	pubKeyHashBytes, err := hex.DecodeString(msg.PubKeyHashSha256)
	if err != nil {
		return fmt.Errorf("pub_key_hash_sha256 is not valid hex: %w", err)
	}
	var pubKeyHashSHA256 [32]byte
	copy(pubKeyHashSHA256[:], pubKeyHashBytes)

	qbtcAddressHash := zk.HashQBTCAddress(recipientBech32)

	chainID := sdkCtx.ChainID()
	chainIDHash := zk.ComputeChainIDHash(chainID)

	messageHash := zk.ComputeClaimMessage(addressHash, qbtcAddressHash, chainIDHash)

	params := zk.VerificationParams{
		MessageHash:      messageHash,
		AddressHash:      addressHash,
		PubKeyHashSHA256: pubKeyHashSHA256,
		QBTCAddressHash:  qbtcAddressHash,
		ChainID:          chainIDHash,
	}

	return zk.VerifyProofGlobal(proofBytes, params)
}
