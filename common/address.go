package common

import (
	"fmt"
	"regexp"
	"strings"

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

	return Address(address), nil
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
	return string(addr)
}
