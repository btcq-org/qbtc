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
// It looks up all specified UTXOs, verifies they belong to the same Bitcoin address,
// verifies the ZK proof against that address, and releases the claimed assets to the claimer.
// All UTXOs are claimed atomically - either all succeed or none are claimed.
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

	// Validate all UTXOs exist, are claimable, and belong to the same address
	var addressHash [20]byte
	var btcAddress string
	utxoAmounts := make([]uint64, len(msg.Utxos))

	for i, utxoRef := range msg.Utxos {
		utxoKey := getUTXOKey(utxoRef.Txid, utxoRef.Vout)
		utxo, err := s.k.Utxoes.Get(sdkCtx, utxoKey)
		if err != nil {
			return nil, sdkerror.ErrNotFound.Wrapf("UTXO[%d] not found: txid=%s, vout=%d", i, utxoRef.Txid, utxoRef.Vout)
		}

		// Check if UTXO has already been claimed
		if utxo.EntitledAmount == 0 {
			return nil, sdkerror.ErrInvalidRequest.Wrapf("UTXO[%d] has already been claimed: txid=%s, vout=%d", i, utxoRef.Txid, utxoRef.Vout)
		}

		// Extract the address hash from the UTXO's ScriptPubKey
		if utxo.ScriptPubKey == nil || utxo.ScriptPubKey.Address == "" {
			return nil, sdkerror.ErrInvalidRequest.Wrapf("UTXO[%d] has no address in ScriptPubKey", i)
		}

		// Convert the Bitcoin address to Hash160
		utxoAddressHash, err := zk.BitcoinAddressToHash160(utxo.ScriptPubKey.Address)
		if err != nil {
			return nil, sdkerror.ErrInvalidRequest.Wrapf("UTXO[%d]: failed to extract address hash: %v", i, err)
		}

		// For the first UTXO, store the address hash as the reference
		if i == 0 {
			addressHash = utxoAddressHash
			btcAddress = utxo.ScriptPubKey.Address
		} else {
			// All subsequent UTXOs must have the same address
			if !bytes.Equal(addressHash[:], utxoAddressHash[:]) {
				return nil, sdkerror.ErrInvalidRequest.Wrapf(
					"UTXO[%d] belongs to different address: expected %s, got %s",
					i, btcAddress, utxo.ScriptPubKey.Address,
				)
			}
		}

		utxoAmounts[i] = utxo.EntitledAmount
	}

	// Verify the ZK proof against the common address
	if err := s.verifyProof(sdkCtx, msg, addressHash); err != nil {
		return nil, sdkerror.ErrInvalidRequest.Wrapf("proof verification failed: %v", err)
	}

	// Use cache context for atomic batch claim
	cacheCtx, write := sdkCtx.CacheContext()

	var totalClaimed uint64
	for i, utxoRef := range msg.Utxos {
		if err := s.k.ClaimUTXO(cacheCtx, utxoRef.Txid, utxoRef.Vout, claimerAddr); err != nil {
			return nil, sdkerror.ErrInvalidRequest.Wrapf("failed to claim UTXO[%d]: %v", i, err)
		}
		totalClaimed += utxoAmounts[i]
	}

	// Commit all claims atomically
	write()

	// Emit batch event
	sdkCtx.EventManager().EmitEvent(
		sdk.NewEvent(
			"claim_with_proof",
			sdk.NewAttribute("claimer", msg.Claimer),
			sdk.NewAttribute("btc_address", btcAddress),
			sdk.NewAttribute("utxos_claimed", fmt.Sprintf("%d", len(msg.Utxos))),
			sdk.NewAttribute("total_amount", fmt.Sprintf("%d", totalClaimed)),
		),
	)

	sdkCtx.Logger().Info("batch claimed with proof",
		"claimer", msg.Claimer,
		"btc_address", btcAddress,
		"utxos_claimed", len(msg.Utxos),
		"total_amount", totalClaimed,
	)

	return &types.MsgClaimWithProofResponse{
		TotalAmountClaimed: totalClaimed,
		UtxosClaimed:       uint32(len(msg.Utxos)),
	}, nil
}

// verifyProof verifies the ZK proof for the claim.
// The proof must demonstrate knowledge of the private key for the given addressHash.
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

	// Build verification params using the address hash from the UTXO
	params := zk.VerificationParams{
		AddressHash:     addressHash,
		BTCQAddressHash: btcqAddressHash,
		ChainID:         chainIDHash,
	}

	// Verify the proof using the global verifier
	return zk.VerifyProofGlobal(proof, params)
}
