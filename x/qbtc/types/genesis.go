package types

import (
	fmt "fmt"
	"net"

	sdk "github.com/cosmos/cosmos-sdk/types"
)

// DefaultGenesis returns the default genesis state
func DefaultGenesis() *GenesisState {
	return &GenesisState{}
}

// Validate performs basic genesis state validation returning an error upon any
// failure.
func (gs GenesisState) Validate() error {
	for _, nodeIP := range gs.NodeIPs {
		if net.ParseIP(nodeIP.IP) == nil {
			return fmt.Errorf("invalid IP address: %s", nodeIP.IP)
		}
		if nodeIP.Validator == "" {
			return fmt.Errorf("validator cannot be empty")
		}
		_, err := sdk.ValAddressFromBech32(nodeIP.Validator)
		if err != nil {
			return fmt.Errorf("invalid validator address: %s", err)
		}
	}
	return nil
}
