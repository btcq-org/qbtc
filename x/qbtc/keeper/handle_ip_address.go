package keeper

import (
	"context"
	"errors"

	"github.com/btcq-org/qbtc/x/qbtc/types"
	sdk "github.com/cosmos/cosmos-sdk/types"
	stakingtypes "github.com/cosmos/cosmos-sdk/x/staking/types"
)

func (s *msgServer) SetIPAddress(ctx context.Context, msg *types.MsgSetIPAddress) (*types.MsgEmpty, error) {
	// Validate the message
	if err := msg.ValidateBasic(); err != nil {
		return nil, err
	}

	signerAcc, err := sdk.AccAddressFromBech32(msg.Signer)
	if err != nil {
		return nil, err
	}

	// Convert account address to validator address
	signer := sdk.ValAddress(signerAcc)
	// Get the validator
	validator, err := s.k.stakingKeeper.GetValidator(ctx, signer)
	if err != nil {
		return nil, err
	}

	// Check if the validator is bonded (Active)
	if validator.Status != stakingtypes.Bonded {
		return nil, errors.New("validator is not bonded")
	}

	// Set the IP address
	err = s.k.NodeIPs.Set(ctx, validator.GetOperator(), msg.IPAddress)
	if err != nil {
		return nil, err
	}

	return &types.MsgEmpty{}, nil
}
