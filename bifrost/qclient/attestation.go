package qclient

import (
	"context"
	"fmt"

	"cosmossdk.io/math"
	"github.com/btcq-org/qbtc/x/qbtc/types"
	sdk "github.com/cosmos/cosmos-sdk/types"
	stakingtypes "github.com/cosmos/cosmos-sdk/x/staking/types"
)

func (c *Client) VerifyAttestation(ctx context.Context, block types.BlockGossip) error {
	if block.Attestation == nil {
		return fmt.Errorf("no attestation provided")
	}

	// Get validator address from attestation
	valAddr, err := sdk.ValAddressFromBech32(block.Attestation.Address)
	if err != nil {
		return fmt.Errorf("invalid validator address %s: %w", block.Attestation.Address, err)
	}

	// Query validator by address to get public key
	resp, err := c.stakingClient.Validator(ctx, &stakingtypes.QueryValidatorRequest{
		ValidatorAddr: block.Attestation.Address,
	})
	if err != nil {
		return fmt.Errorf("failed to query validator %s: %w", valAddr.String(), err)
	}

	if resp.Validator.Status != stakingtypes.Bonded {
		return fmt.Errorf("validator %s is not bonded (status: %s)", valAddr.String(), resp.Validator.Status.String())
	}

	// Get consensus public key from validator
	publicKey, err := resp.Validator.ConsPubKey()
	if err != nil {
		return fmt.Errorf("failed to get consensus public key for validator %s: %w", valAddr.String(), err)
	}

	// Verify signature against block content
	if !publicKey.VerifySignature(block.BlockContent, block.Attestation.Signature) {
		return fmt.Errorf("signature verification failed for validator %s", valAddr.String())
	}

	c.logger.Debug().
		Str("validator", block.Attestation.Address).
		Uint64("height", block.Height).
		Str("hash", block.Hash).
		Msg("attestation verified successfully")

	return nil
}

func (c *Client) CheckAttestationsSuperMajority(ctx context.Context, msg *types.MsgBtcBlock) error {
	if msg == nil {
		return fmt.Errorf("no attestations provided")
	}

	// Get all active validators
	activeValidators, err := c.ActiveValidators(ctx)
	if err != nil {
		return fmt.Errorf("failed to get validators: %w", err)
	}

	// Get total voting power from the pool
	poolResp, err := c.stakingClient.Pool(ctx, &stakingtypes.QueryPoolRequest{})
	if err != nil {
		return fmt.Errorf("failed to get staking pool: %w", err)
	}
	if poolResp == nil || poolResp.Pool.BondedTokens.IsZero() {
		return fmt.Errorf("invalid pool state: bonded tokens is zero")
	}

	totalVotingPower := math.NewInt(sdk.TokensToConsensusPower(poolResp.Pool.BondedTokens, sdk.DefaultPowerReduction))

	// Create a map of validators by address for quick lookup
	validatorsByAddr := make(map[string]stakingtypes.Validator, len(activeValidators))
	for _, validator := range activeValidators {
		validatorsByAddr[validator.OperatorAddress] = validator
	}

	// Track processed validators to avoid duplicates
	processedValidators := make(map[string]bool, len(msg.Attestations))
	validPower := math.ZeroInt()

	// Iterate through attestations and verify each one
	for _, attestation := range msg.Attestations {
		if attestation == nil {
			c.logger.Warn().Msg("skipping nil attestation")
			continue
		}

		// Skip duplicate attestations from the same validator
		if processedValidators[attestation.Address] {
			c.logger.Debug().
				Str("validator", attestation.Address).
				Msg("skipping duplicate attestation")
			continue
		}

		// Validate validator address
		_, err := sdk.ValAddressFromBech32(attestation.Address)
		if err != nil {
			c.logger.Error().
				Err(err).
				Str("address", attestation.Address).
				Msg("invalid validator address in attestation")
			continue
		}

		// Look up validator in our map
		validator, found := validatorsByAddr[attestation.Address]
		if !found {
			c.logger.Error().
				Str("address", attestation.Address).
				Msg("validator not found or not bonded")
			continue
		}

		// Get consensus public key (in this case consensus and account keys are the same)
		publicKey, err := validator.ConsPubKey()
		if err != nil {
			c.logger.Error().
				Err(err).
				Str("address", attestation.Address).
				Msg("failed to get consensus public key")
			continue
		}

		// Verify signature against block content
		if publicKey.VerifySignature(msg.BlockContent, attestation.Signature) {
			validatorPower := math.NewInt(validator.ConsensusPower(sdk.DefaultPowerReduction))
			validPower = validPower.Add(validatorPower)

			c.logger.Debug().
				Str("validator", attestation.Address).
				Str("power", validatorPower.String()).
				Str("total_valid_power", validPower.String()).
				Msg("valid attestation")
		} else {
			c.logger.Warn().
				Str("validator", attestation.Address).
				Msg("signature verification failed")
		}

		processedValidators[attestation.Address] = true
	}

	// Require more than 2/3 of total staking power to attest the block
	requiredPower := totalVotingPower.Mul(math.NewInt(2)).Quo(math.NewInt(3))

	if validPower.LTE(requiredPower) {
		return fmt.Errorf("insufficient voting power: have %s, required >%s (total: %s)",
			validPower.String(), requiredPower.String(), totalVotingPower.String())
	}

	c.logger.Info().
		Str("valid_power", validPower.String()).
		Str("required_power", requiredPower.String()).
		Str("total_power", totalVotingPower.String()).
		Uint64("height", msg.Height).
		Str("hash", msg.Hash).
		Msg("supermajority attestation verified")

	return nil
}
