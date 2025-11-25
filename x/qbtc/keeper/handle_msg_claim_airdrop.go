package keeper

import (
	"context"
	"encoding/hex"
	"fmt"

	"cosmossdk.io/math"
	"github.com/btcq-org/qbtc/x/qbtc/types"
	"github.com/btcq-org/qbtc/x/qbtc/zk"
	sdk "github.com/cosmos/cosmos-sdk/types"
	sdkerror "github.com/cosmos/cosmos-sdk/types/errors"
)

// ClaimAirdrop handles the MsgClaimAirdrop message
// It verifies the ZK proof and releases the airdrop to the claimer
func (s *msgServer) ClaimAirdrop(ctx context.Context, msg *types.MsgClaimAirdrop) (*types.MsgClaimAirdropResponse, error) {
	// Validate the message
	if err := msg.ValidateBasic(); err != nil {
		return nil, err
	}

	sdkCtx := sdk.UnwrapSDKContext(ctx)

	// Convert address hash to hex key
	addressHashHex := hex.EncodeToString(msg.BtcAddressHash)

	// Check if this airdrop has already been claimed
	claimed, err := s.k.ClaimedAirdrops.Get(sdkCtx, addressHashHex)
	if err == nil && claimed {
		return nil, sdkerror.ErrInvalidRequest.Wrap("airdrop already claimed for this address")
	}

	// Check if the address is eligible for an airdrop
	airdropAmount, err := s.k.AirdropEntries.Get(sdkCtx, addressHashHex)
	if err != nil {
		return nil, sdkerror.ErrInvalidRequest.Wrapf("address not eligible for airdrop: %s", addressHashHex)
	}

	if airdropAmount == 0 {
		return nil, sdkerror.ErrInvalidRequest.Wrap("airdrop amount is zero")
	}

	// Verify the ZK proof
	if err := s.verifyAirdropProof(msg); err != nil {
		return nil, sdkerror.ErrInvalidRequest.Wrapf("proof verification failed: %v", err)
	}

	// Parse the claimer address
	claimerAddr, err := sdk.AccAddressFromBech32(msg.Claimer)
	if err != nil {
		return nil, sdkerror.ErrInvalidAddress.Wrapf("invalid claimer address: %v", err)
	}

	// Mint and send the airdrop tokens to the claimer
	if err := s.k.releaseAirdrop(sdkCtx, claimerAddr, airdropAmount); err != nil {
		return nil, sdkerror.ErrInsufficientFunds.Wrapf("failed to release airdrop: %v", err)
	}

	// Mark the airdrop as claimed
	if err := s.k.ClaimedAirdrops.Set(sdkCtx, addressHashHex, true); err != nil {
		return nil, sdkerror.ErrLogic.Wrapf("failed to mark airdrop as claimed: %v", err)
	}

	// Emit event
	sdkCtx.EventManager().EmitEvent(
		sdk.NewEvent(
			"airdrop_claimed",
			sdk.NewAttribute("claimer", msg.Claimer),
			sdk.NewAttribute("btc_address_hash", addressHashHex),
			sdk.NewAttribute("amount", fmt.Sprintf("%d", airdropAmount)),
		),
	)

	sdkCtx.Logger().Info("airdrop claimed",
		"claimer", msg.Claimer,
		"btc_address_hash", addressHashHex,
		"amount", airdropAmount,
	)

	return &types.MsgClaimAirdropResponse{
		AmountClaimed: airdropAmount,
	}, nil
}

// verifyAirdropProof verifies the ZK proof for an airdrop claim
func (s *msgServer) verifyAirdropProof(msg *types.MsgClaimAirdrop) error {
	// Check if the default verifier is initialized
	if zk.DefaultVerifier == nil {
		return fmt.Errorf("ZK verifier not initialized")
	}

	// Convert the proof from proto format
	proof, err := zk.ProofFromProtoZKProof(msg.Proof.ProofData)
	if err != nil {
		return fmt.Errorf("invalid proof format: %w", err)
	}

	// Compute the btcq address hash for binding
	btcqAddressHash := zk.HashBTCQAddress(msg.Claimer)

	// Convert address hash to fixed-size array
	var addressHash [20]byte
	copy(addressHash[:], msg.BtcAddressHash)

	// Verify the proof
	return zk.DefaultVerifier.VerifyProof(proof, addressHash, btcqAddressHash)
}

// releaseAirdrop sends the airdrop tokens to the claimer
func (k Keeper) releaseAirdrop(ctx sdk.Context, claimer sdk.AccAddress, amount uint64) error {
	// Get the airdrop denomination from params or use default
	denom := "uqbtc" // TODO: make this configurable via params

	// Create the coins to send
	coins := sdk.NewCoins(sdk.NewCoin(denom, math.NewIntFromUint64(amount)))

	// Send from the module account to the claimer
	return k.bankKeeper.SendCoinsFromModuleToAccount(ctx, types.ModuleName, claimer, coins)
}

// SetAirdropEntry sets an airdrop entry for a given address hash
func (k Keeper) SetAirdropEntry(ctx context.Context, addressHashHex string, amount uint64) error {
	return k.AirdropEntries.Set(ctx, addressHashHex, amount)
}

// GetAirdropEntry retrieves an airdrop entry for a given address hash
func (k Keeper) GetAirdropEntry(ctx context.Context, addressHashHex string) (uint64, error) {
	return k.AirdropEntries.Get(ctx, addressHashHex)
}

// IsAirdropClaimed checks if an airdrop has been claimed for a given address hash
func (k Keeper) IsAirdropClaimed(ctx context.Context, addressHashHex string) (bool, error) {
	claimed, err := k.ClaimedAirdrops.Get(ctx, addressHashHex)
	if err != nil {
		return false, nil // Not found means not claimed
	}
	return claimed, nil
}

// GetAllAirdropEntries returns all airdrop entries
func (k Keeper) GetAllAirdropEntries(ctx context.Context) ([]types.AirdropEntry, error) {
	var entries []types.AirdropEntry

	iter, err := k.AirdropEntries.Iterate(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer iter.Close()

	for ; iter.Valid(); iter.Next() {
		key, err := iter.Key()
		if err != nil {
			return nil, err
		}
		value, err := iter.Value()
		if err != nil {
			return nil, err
		}

		// Check if claimed
		claimed, _ := k.IsAirdropClaimed(ctx, key)

		// Convert hex key to bytes
		addressHash, err := hex.DecodeString(key)
		if err != nil {
			continue
		}

		entries = append(entries, types.AirdropEntry{
			AddressHash: addressHash,
			Amount:      value,
			Claimed:     claimed,
		})
	}

	return entries, nil
}
