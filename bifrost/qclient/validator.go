package qclient

import (
	"context"

	"cosmossdk.io/math"
	sdk "github.com/cosmos/cosmos-sdk/types"
	stakingtypes "github.com/cosmos/cosmos-sdk/x/staking/types"
)

func (c *Client) Validator(ctx context.Context, address string) (stakingtypes.Validator, error) {
	resp, err := c.stakingClient.Validator(ctx, &stakingtypes.QueryValidatorRequest{
		ValidatorAddr: address,
	})
	if err != nil {
		return stakingtypes.Validator{}, err
	}
	return resp.Validator, nil
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

func (c *Client) ValidatorsVotingPower(ctx context.Context, validators []stakingtypes.Validator) []ValidatorVotingPower {
	powerReduction := sdk.DefaultPowerReduction

	// get total voting power
	totalVotingPower := math.ZeroInt()
	validatorVotingPowers := make([]math.Int, len(validators))
	for i, validator := range validators {
		power := math.NewInt(validator.ConsensusPower(powerReduction))
		validatorVotingPowers[i] = power
		totalVotingPower = totalVotingPower.Add(power)
	}

	// calculate share per validator
	totalDec := math.LegacyNewDecFromInt(totalVotingPower)
	votingPower := make([]ValidatorVotingPower, len(validators))
	for i, validator := range validators {
		var share math.LegacyDec
		if !totalVotingPower.IsZero() {
			valVPDec := math.LegacyNewDecFromInt(validatorVotingPowers[i])
			share = valVPDec.Quo(totalDec).MulInt64(100)
		} else {
			share = math.LegacyZeroDec()
		}
		votingPower[i] = ValidatorVotingPower{
			Validator:   validator,
			VotingPower: validatorVotingPowers[i].Int64(),
			Share:       share,
		}
	}
	return votingPower
}
