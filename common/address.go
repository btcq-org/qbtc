package common

import (
	"btcq/app"
	"fmt"
	"regexp"
	"strings"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/cosmos/btcutil/bech32"
	sdk "github.com/cosmos/cosmos-sdk/types"
)

type Address string

const (
	NoAddress   = Address("")
	NoopAddress = Address("noop")
)

var alphaNumRegex = regexp.MustCompile("^[:A-Za-z0-9]*$")

func NewAddress(address string) (Address, error) {
	if len(address) == 0 {
		return NoAddress, nil
	}

	if !alphaNumRegex.MatchString(address) {
		return NoAddress, fmt.Errorf("address format not supported: %s", address)
	}
	if address == "noop" {
		return NoopAddress, nil
	}
	// BTCQ address
	hrp, _, err := bech32.DecodeNoLimit(address)
	if err == nil && hrp == app.AccountAddressPrefix {
		return Address(address), nil
	}

	// Check other BTC address formats with mainnet
	outputAddr, err := btcutil.DecodeAddress(address, getChainNetParameter())
	if err != nil {
		return NoAddress, fmt.Errorf("address format not supported: %s", address)
	}
	switch outputAddr.(type) {
	case *btcutil.AddressPubKey:
		return NoAddress, fmt.Errorf("public key address format not supported: %s", address)
		// AddressPubKey format is not supported by THORChain.
	default:
		return Address(address), nil
	}
}
func getChainNetParameter() *chaincfg.Params {
	switch CurrentChainNetwork {
	case MainNet, StageNet:
		return &chaincfg.MainNetParams
	case MockNet:
		return &chaincfg.RegressionNetParams
	case TestNet:
		return &chaincfg.TestNet3Params
	}
	return &chaincfg.MainNetParams
}
func (addr Address) AccAddress() (sdk.AccAddress, error) {
	return sdk.AccAddressFromBech32(addr.String())
}

func (addr Address) Equals(addr2 Address) bool {
	return addr.String() == addr2.String()
}

func (addr Address) IsEmpty() bool {
	return strings.TrimSpace(addr.String()) == ""
}

func (addr Address) IsNoop() bool {
	return addr.Equals(NoopAddress)
}

func (addr Address) String() string {
	if addr == NoAddress {
		return ""
	}
	return string(addr)
}
