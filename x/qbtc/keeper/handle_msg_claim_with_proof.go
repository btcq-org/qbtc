package keeper

import (
	"bytes"
	"context"
	"fmt"

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
	// Validate the message
	if err := msg.ValidateBasic(); err != nil {
		return nil, err
	}

	sdkCtx := sdk.UnwrapSDKContext(ctx)

	// Ensure the ZK verifier is initialized
	if !zk.IsVerifierInitialized() {
		return nil, sdkerror.ErrInvalidRequest.Wrap("ZK verifier not initialized - genesis VK not loaded")
	}

	// Parse the claimer address upfront
	claimerAddr, err := sdk.AccAddressFromBech32(msg.Claimer)
	if err != nil {
		return nil, sdkerror.ErrInvalidAddress.Wrapf("invalid claimer address: %v", err)
	}

	// Find the first valid UTXO to determine the proven address
	var provenAddressHash [20]byte
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

		addressHash, err := zk.BitcoinAddressToHash160(utxo.ScriptPubKey.Address)
		if err != nil {
			continue // Skip UTXOs with invalid addresses
		}

		// Found a valid UTXO - use its address for proof verification
		provenAddressHash = addressHash
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

	// Verify the ZK proof against the determined address
	if err := s.verifyProof(sdkCtx, msg, provenAddressHash); err != nil {
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

		utxoAddressHash, err := zk.BitcoinAddressToHash160(utxo.ScriptPubKey.Address)
		if err != nil {
			skippedCount++
			sdkCtx.Logger().Debug("skipping UTXO: invalid address format",
				"index", i, "txid", utxoRef.Txid, "vout", utxoRef.Vout, "error", err)
			continue
		}

		// Check if this UTXO's address matches the proven address
		if !bytes.Equal(provenAddressHash[:], utxoAddressHash[:]) {
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
		if err := s.k.ClaimUTXO(cacheCtx, utxo.txid, utxo.vout, claimerAddr); err != nil {
			return nil, sdkerror.ErrInvalidRequest.Wrapf("failed to claim UTXO[%d]: %v", utxo.index, err)
		}
		totalClaimed += utxo.amount
	}

	// Commit all claims atomically
	write()

	// Emit batch event
	sdkCtx.EventManager().EmitEvent(
		sdk.NewEvent(
			"claim_with_proof",
			sdk.NewAttribute("claimer", msg.Claimer),
			sdk.NewAttribute("btc_address", provenBtcAddress),
			sdk.NewAttribute("utxos_claimed", fmt.Sprintf("%d", len(claimableUTXOs))),
			sdk.NewAttribute("utxos_skipped", fmt.Sprintf("%d", skippedCount)),
			sdk.NewAttribute("total_amount", fmt.Sprintf("%d", totalClaimed)),
		),
	)

	sdkCtx.Logger().Info("batch claimed with proof",
		"claimer", msg.Claimer,
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

// verifyProof verifies the ZK proof for the claim.
// The proof must demonstrate a valid ECDSA signature from the key that controls the Bitcoin address.
func (s *msgServer) verifyProof(sdkCtx sdk.Context, msg *types.MsgClaimWithProof, addressHash [20]byte) error {
	// Convert the proof from proto format
	proof, err := zk.ProofFromProtoZKProof(msg.Proof.ProofData)
	if err != nil {
		return fmt.Errorf("invalid proof format: %w", err)
	}

	// Compute the btcq address hash for binding (prevents front-running)
	btcqAddressHash := zk.HashBTCQAddress(msg.Claimer)

	// Compute chain ID hash from the chain ID (prevents cross-chain replay)
	chainID := sdkCtx.ChainID()
	chainIDHash := zk.ComputeChainIDHash(chainID)

	// Compute expected message hash that should have been signed
	messageHash := zk.ComputeClaimMessage(addressHash, btcqAddressHash, chainIDHash)

	// Build verification params
	params := zk.VerificationParams{
		MessageHash:     messageHash,
		AddressHash:     addressHash,
		BTCQAddressHash: btcqAddressHash,
		ChainID:         chainIDHash,
	}

	// Verify the proof using the global verifier
	return zk.VerifyProofGlobal(proof, params)
}
