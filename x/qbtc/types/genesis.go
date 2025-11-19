package types

import (
	"fmt"

	sdk "github.com/cosmos/cosmos-sdk/types"
)

// DefaultGenesis returns the default genesis state
func DefaultGenesis() *GenesisState {
	return &GenesisState{}
}

// Validate performs basic genesis state validation returning an error upon any
// failure.
func (gs GenesisState) Validate() error {
	for _, nodePeerAddress := range gs.PeerAddresses {
		if nodePeerAddress.Validator == "" {
			return fmt.Errorf("validator cannot be empty")
		}
		_, err := sdk.ValAddressFromBech32(nodePeerAddress.Validator)
		if err != nil {
			return fmt.Errorf("invalid validator address: %s", err)
		}
		if err := ValidatePeerAddress(nodePeerAddress.PeerAddress); err != nil {
			return fmt.Errorf("invalid peer address: %w", err)
		}
	}
	return nil
}
