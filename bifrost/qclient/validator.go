package qclient

import (
	"context"
	"errors"

	"cosmossdk.io/math"
	sdk "github.com/cosmos/cosmos-sdk/types"
	stakingtypes "github.com/cosmos/cosmos-sdk/x/staking/types"
)

func (c *Client) Validator(ctx context.Context, address string) (ValidatorVotingPower, error) {
	resp, err := c.stakingClient.Validator(ctx, &stakingtypes.QueryValidatorRequest{
		ValidatorAddr: address,
	})
	if err != nil {
		return ValidatorVotingPower{}, err
	}
	poolResp, err := c.stakingClient.Pool(ctx, &stakingtypes.QueryPoolRequest{})
	if err != nil {
		return ValidatorVotingPower{}, err
	}
	if poolResp == nil {
		return ValidatorVotingPower{}, errors.New("pool response is nil")
	}
	if poolResp.Pool.BondedTokens.IsZero() {
		return ValidatorVotingPower{}, errors.New("pool bonded tokens is zero")
	}
	totalVotingPower := sdk.TokensToConsensusPower(poolResp.Pool.BondedTokens, sdk.DefaultPowerReduction)
	votingPower := resp.Validator.ConsensusPower(sdk.DefaultPowerReduction)
	return ValidatorVotingPower{
		Validator:   resp.Validator,
		VotingPower: votingPower,
		Share:       math.LegacyNewDecFromInt(math.NewInt(votingPower)).Quo(math.LegacyNewDecFromInt(math.NewInt(totalVotingPower))),
	}, nil
}

func (c *Client) ActiveValidators(ctx context.Context) ([]stakingtypes.Validator, error) {
	resp, err := c.stakingClient.Validators(ctx, &stakingtypes.QueryValidatorsRequest{
		Status: stakingtypes.Bonded.String(),
	})
	if err != nil {
		return nil, err
	}
	return resp.Validators, nil
}

func (c *Client) TotalVotingPower(ctx context.Context, validators []stakingtypes.Validator) int64 {
	totalVotingPower := int64(0)
	powerReduction := sdk.DefaultPowerReduction
	for _, validator := range validators {
		totalVotingPower += validator.ConsensusPower(powerReduction)
	}
	return totalVotingPower
}

type ValidatorVotingPower struct {
	Validator   stakingtypes.Validator
	VotingPower int64
	Share       math.LegacyDec // Percentage share of total voting power
}

func (c *Client) ValidatorsVotingPower(ctx context.Context, validators []stakingtypes.Validator) ([]ValidatorVotingPower, error) {
	powerReduction := sdk.DefaultPowerReduction

	// get total voting power from Pool (more efficient than summing all validators)
	poolResp, err := c.stakingClient.Pool(ctx, &stakingtypes.QueryPoolRequest{})
	if err != nil {
		return nil, err
	}
	if poolResp == nil {
		return nil, errors.New("pool response is nil")
	}
	totalVotingPower := sdk.TokensToConsensusPower(poolResp.Pool.BondedTokens, powerReduction)

	// calculate individual validator voting powers and shares
	validatorVotingPowers := make([]math.Int, len(validators))
	for i, validator := range validators {
		validatorVotingPowers[i] = math.NewInt(validator.ConsensusPower(powerReduction))
	}

	// calculate share per validator
	totalDec := math.LegacyNewDecFromInt(math.NewInt(totalVotingPower))
	votingPower := make([]ValidatorVotingPower, len(validators))
	for i, validator := range validators {
		var share math.LegacyDec
		if !totalDec.IsZero() {
			valVPDec := math.LegacyNewDecFromInt(validatorVotingPowers[i])
			share = valVPDec.Quo(totalDec)
		} else {
			share = math.LegacyZeroDec()
		}
		votingPower[i] = ValidatorVotingPower{
			Validator:   validator,
			VotingPower: validatorVotingPowers[i].Int64(),
			Share:       share,
		}
	}
	return votingPower, nil
}
