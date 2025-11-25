package keeper

import (
	"context"
	"crypto/sha256"
	"fmt"

	"github.com/btcq-org/qbtc/constants"
	"github.com/btcq-org/qbtc/x/qbtc/types"
	"github.com/btcq-org/qbtc/x/qbtc/zk"
	sdk "github.com/cosmos/cosmos-sdk/types"
	sdkerror "github.com/cosmos/cosmos-sdk/types/errors"
	stakingtypes "github.com/cosmos/cosmos-sdk/x/staking/types"
)

// SubmitZKEntropy handles the MsgSubmitZKEntropy message.
// It allows validators to submit entropy for the distributed ZK trusted setup.
func (s *msgServer) SubmitZKEntropy(ctx context.Context, msg *types.MsgSubmitZKEntropy) (*types.MsgSubmitZKEntropyResponse, error) {
	// Validate the message
	if err := msg.ValidateBasic(); err != nil {
		return nil, err
	}

	sdkCtx := sdk.UnwrapSDKContext(ctx)

	// Verify the sender is an active validator
	valAddr, err := sdk.ValAddressFromBech32(msg.Validator)
	if err != nil {
		return nil, sdkerror.ErrInvalidAddress.Wrapf("invalid validator address: %v", err)
	}

	validator, err := s.k.stakingKeeper.Validator(ctx, valAddr)
	if err != nil || validator == nil {
		return nil, sdkerror.ErrUnauthorized.Wrap("sender is not a registered validator")
	}

	if validator.GetStatus() != stakingtypes.Bonded {
		return nil, sdkerror.ErrUnauthorized.Wrap("validator is not bonded")
	}

	// Get the current entropy state
	state, err := s.k.GetZKEntropyState(ctx)
	if err != nil {
		// Initialize state if it doesn't exist
		state = types.ZKEntropyState{
			CollectionActive:     false,
			CollectionStartBlock: 0,
			Submissions:          []types.ZKEntropySubmission{},
			SetupFinalized:       false,
		}
	}

	// Check if setup has already been finalized
	if state.SetupFinalized {
		return nil, sdkerror.ErrInvalidRequest.Wrap("ZK setup has already been finalized")
	}

	// Check if this validator has already submitted
	_, err = s.k.ZKEntropySubmissions.Get(ctx, msg.Validator)
	if err == nil {
		return nil, sdkerror.ErrInvalidRequest.Wrap("validator has already submitted entropy")
	}

	// Verify the commitment matches the entropy
	expectedCommitment := computeEntropyCommitment(msg.Entropy, msg.Validator)
	if !bytesEqual(expectedCommitment, msg.Commitment) {
		return nil, sdkerror.ErrInvalidRequest.Wrap("commitment does not match entropy")
	}

	// Get the threshold from constants
	threshold := s.k.GetConfig(sdkCtx, constants.ZKEntropyThreshold)
	blockWindow := s.k.GetConfig(sdkCtx, constants.ZKEntropyBlockWindow)
	currentBlock := sdkCtx.BlockHeight()

	// If collection hasn't started and we have enough validators, start it
	if !state.CollectionActive {
		// Count active bonded validators
		activeValidators, err := s.k.countActiveValidators(ctx)
		if err != nil {
			return nil, sdkerror.ErrLogic.Wrapf("failed to count validators: %v", err)
		}

		if activeValidators < int(threshold) {
			return nil, sdkerror.ErrInvalidRequest.Wrapf(
				"not enough active validators: have %d, need %d",
				activeValidators, threshold,
			)
		}

		// Start collection
		state.CollectionActive = true
		state.CollectionStartBlock = currentBlock
	}

	// Check if we're still within the block window
	if currentBlock > state.CollectionStartBlock+blockWindow {
		return nil, sdkerror.ErrInvalidRequest.Wrapf(
			"entropy collection window has expired at block %d (current: %d)",
			state.CollectionStartBlock+blockWindow, currentBlock,
		)
	}

	// Store the submission
	submission := types.ZKEntropySubmission{
		Validator:        msg.Validator,
		Entropy:          msg.Entropy,
		SubmittedAtBlock: currentBlock,
		Commitment:       msg.Commitment,
	}

	if err := s.k.ZKEntropySubmissions.Set(ctx, msg.Validator, submission); err != nil {
		return nil, sdkerror.ErrLogic.Wrapf("failed to store entropy submission: %v", err)
	}

	// Update the state with the new submission
	state.Submissions = append(state.Submissions, submission)

	// Check if we've reached the threshold
	submissionCount := uint64(len(state.Submissions))
	thresholdReached := submissionCount >= uint64(threshold)

	// If threshold reached, finalize the setup
	if thresholdReached {
		if err := s.k.finalizeZKSetup(ctx, &state); err != nil {
			// Don't fail the transaction, just log the error
			sdkCtx.Logger().Error("failed to finalize ZK setup", "error", err)
		}
	}

	// Save the updated state
	if err := s.k.ZKEntropyState.Set(ctx, state); err != nil {
		return nil, sdkerror.ErrLogic.Wrapf("failed to save entropy state: %v", err)
	}

	// Emit event
	sdkCtx.EventManager().EmitEvent(
		sdk.NewEvent(
			"zk_entropy_submitted",
			sdk.NewAttribute("validator", msg.Validator),
			sdk.NewAttribute("submission_count", fmt.Sprintf("%d", submissionCount)),
			sdk.NewAttribute("threshold_reached", fmt.Sprintf("%t", thresholdReached)),
		),
	)

	sdkCtx.Logger().Info("ZK entropy submitted",
		"validator", msg.Validator,
		"submission_count", submissionCount,
		"threshold_reached", thresholdReached,
	)

	return &types.MsgSubmitZKEntropyResponse{
		SubmissionCount:       submissionCount,
		ThresholdReached:      thresholdReached,
		CollectionStartBlock:  state.CollectionStartBlock,
	}, nil
}

// GetZKEntropyState retrieves the current entropy collection state
func (k Keeper) GetZKEntropyState(ctx context.Context) (types.ZKEntropyState, error) {
	return k.ZKEntropyState.Get(ctx)
}

// GetZKSetupKeys retrieves the finalized setup keys
func (k Keeper) GetZKSetupKeys(ctx context.Context) (types.ZKSetupKeys, error) {
	return k.ZKSetupKeys.Get(ctx)
}

// countActiveValidators counts the number of bonded validators
func (k Keeper) countActiveValidators(ctx context.Context) (int, error) {
	count := 0
	err := k.stakingKeeper.IterateBondedValidatorsByPower(ctx, func(index int64, validator stakingtypes.ValidatorI) (stop bool) {
		count++
		return false
	})
	if err != nil {
		return 0, err
	}
	return count, nil
}

// finalizeZKSetup combines all entropy submissions and generates the setup keys
func (k Keeper) finalizeZKSetup(ctx context.Context, state *types.ZKEntropyState) error {
	sdkCtx := sdk.UnwrapSDKContext(ctx)

	if len(state.Submissions) == 0 {
		return fmt.Errorf("no entropy submissions to combine")
	}

	// Combine all entropy using XOR and then hash
	// This ensures that as long as one validator provided good entropy,
	// the combined result is unpredictable
	combinedEntropy := combineEntropy(state.Submissions)

	// Hash the combined entropy to create the seed
	combinedSeed := sha256.Sum256(combinedEntropy)

	// Generate the ZK setup using the deterministic seed
	setupResult, err := zk.SetupWithSeed(combinedSeed[:])
	if err != nil {
		return fmt.Errorf("failed to generate ZK setup: %w", err)
	}

	// Serialize the verifying key
	vkBytes, err := zk.SerializeVerifyingKey(setupResult.VerifyingKey)
	if err != nil {
		return fmt.Errorf("failed to serialize verifying key: %w", err)
	}

	// Collect contributing validators
	var contributors []string
	for _, sub := range state.Submissions {
		contributors = append(contributors, sub.Validator)
	}

	// Create the setup keys record
	seedHash := sha256.Sum256(combinedSeed[:])
	setupKeys := types.ZKSetupKeys{
		VerifyingKey:           vkBytes,
		SeedHash:               seedHash[:],
		GeneratedAtBlock:       sdkCtx.BlockHeight(),
		ContributingValidators: contributors,
	}

	// Store the setup keys
	if err := k.ZKSetupKeys.Set(ctx, setupKeys); err != nil {
		return fmt.Errorf("failed to store setup keys: %w", err)
	}

	// Update state
	state.SetupFinalized = true
	state.CombinedSeed = combinedSeed[:]
	state.FinalizedAtBlock = sdkCtx.BlockHeight()

	// Initialize the default verifier with the new key
	if err := zk.InitDefaultVerifier(vkBytes); err != nil {
		sdkCtx.Logger().Error("failed to initialize default verifier", "error", err)
		// Don't fail - the key is stored and can be loaded later
	}

	sdkCtx.Logger().Info("ZK setup finalized",
		"contributors", len(contributors),
		"block", sdkCtx.BlockHeight(),
	)

	// Emit finalization event
	sdkCtx.EventManager().EmitEvent(
		sdk.NewEvent(
			"zk_setup_finalized",
			sdk.NewAttribute("contributors", fmt.Sprintf("%d", len(contributors))),
			sdk.NewAttribute("block", fmt.Sprintf("%d", sdkCtx.BlockHeight())),
		),
	)

	return nil
}

// combineEntropy combines multiple entropy submissions using XOR
// This is secure because XOR preserves randomness: if any input is truly random,
// the output is also truly random (regardless of other inputs being malicious)
func combineEntropy(submissions []types.ZKEntropySubmission) []byte {
	if len(submissions) == 0 {
		return nil
	}

	// Start with the first submission's entropy
	result := make([]byte, len(submissions[0].Entropy))
	copy(result, submissions[0].Entropy)

	// XOR with all other submissions
	for i := 1; i < len(submissions); i++ {
		entropy := submissions[i].Entropy
		for j := 0; j < len(result) && j < len(entropy); j++ {
			result[j] ^= entropy[j]
		}
	}

	// Add a domain separator by hashing with context
	// This prevents any potential related-key attacks
	hasher := sha256.New()
	hasher.Write([]byte("qbtc-zk-entropy-v1"))
	hasher.Write(result)
	for _, sub := range submissions {
		hasher.Write([]byte(sub.Validator))
	}

	return hasher.Sum(nil)
}

// computeEntropyCommitment computes SHA256(entropy || validator_address)
func computeEntropyCommitment(entropy []byte, validator string) []byte {
	hasher := sha256.New()
	hasher.Write(entropy)
	hasher.Write([]byte(validator))
	return hasher.Sum(nil)
}

// bytesEqual compares two byte slices in constant time
func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	result := byte(0)
	for i := 0; i < len(a); i++ {
		result |= a[i] ^ b[i]
	}
	return result == 0
}

// CheckZKEntropyFinalization checks if the ZK entropy collection window has expired
// and finalizes the setup if it hasn't been done yet.
// This is called in EndBlock to handle the case where we have enough submissions
// but the finalization wasn't triggered during the last submission.
func (k Keeper) CheckZKEntropyFinalization(ctx context.Context) error {
	// Get the current entropy state
	state, err := k.GetZKEntropyState(ctx)
	if err != nil {
		// No state means no collection started yet - that's fine
		return nil
	}

	// If already finalized, nothing to do
	if state.SetupFinalized {
		return nil
	}

	// If collection not active, nothing to do
	if !state.CollectionActive {
		return nil
	}

	sdkCtx := sdk.UnwrapSDKContext(ctx)
	currentBlock := sdkCtx.BlockHeight()

	// Get the threshold from constants
	threshold := k.GetConfig(sdkCtx, constants.ZKEntropyThreshold)
	blockWindow := k.GetConfig(sdkCtx, constants.ZKEntropyBlockWindow)

	// Check if we're past the block window
	if currentBlock <= state.CollectionStartBlock+blockWindow {
		// Still within the window, check if we have enough submissions to finalize
		if int64(len(state.Submissions)) >= threshold && !state.SetupFinalized {
			if err := k.finalizeZKSetup(ctx, &state); err != nil {
				return fmt.Errorf("failed to finalize ZK setup: %w", err)
			}
			// Save the updated state
			if err := k.ZKEntropyState.Set(ctx, state); err != nil {
				return fmt.Errorf("failed to save entropy state: %w", err)
			}
		}
		return nil
	}

	// Window has expired
	// If we have enough submissions, finalize
	if int64(len(state.Submissions)) >= threshold {
		if err := k.finalizeZKSetup(ctx, &state); err != nil {
			return fmt.Errorf("failed to finalize ZK setup after window expired: %w", err)
		}
		// Save the updated state
		if err := k.ZKEntropyState.Set(ctx, state); err != nil {
			return fmt.Errorf("failed to save entropy state: %w", err)
		}
		sdkCtx.Logger().Info("ZK setup finalized after collection window expired",
			"submissions", len(state.Submissions),
			"threshold", threshold,
		)
	} else {
		// Not enough submissions - log a warning but don't fail
		sdkCtx.Logger().Warn("ZK entropy collection window expired without enough submissions",
			"submissions", len(state.Submissions),
			"threshold", threshold,
			"window_expired_at", state.CollectionStartBlock+blockWindow,
		)
	}

	return nil
}

