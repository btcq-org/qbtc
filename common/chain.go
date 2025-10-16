package common

import (
	"errors"
	"strings"

	"github.com/btcsuite/btcd/chaincfg"
	"github.com/hashicorp/go-multierror"
)

const (
	EmptyChain = Chain("")
	BTCChain   = Chain("BTC")
	BTCQChain  = Chain("BTCQ")
)

type Chain string
type Chains []Chain

func (c Chain) String() string {
	// convert it to upper case again just in case someone created a ticker via Chain("rune")
	return strings.ToUpper(string(c))
}

// Valid validates chain format, should consist only of uppercase letters
func (c Chain) Valid() error {
	if len(c) < 3 {
		return errors.New("chain id len is less than 3")
	}
	if len(c) > 10 {
		return errors.New("chain id len is more than 10")
	}
	for _, ch := range string(c) {
		if ch < 'A' || ch > 'Z' {
			return errors.New("chain id can consist only of uppercase letters")
		}
	}
	return nil
}
func (c Chain) IsEmpty() bool {
	return strings.TrimSpace(c.String()) == ""
}

// GetGasAsset chain's base asset
func (c Chain) GetGasAsset() Asset {
	switch c {
	case BTCQChain:
		return BTCQAsset
	case BTCChain:
		return BTCAsset
	default:
		return EmptyAsset
	}
}

// NewChain create a new Chain
func NewChain(chainID string) (Chain, error) {
	chain := Chain(strings.ToUpper(chainID))
	if err := chain.Valid(); err != nil {
		return chain, err
	}
	return chain, nil
}
func (c Chain) AddressPrefix(cn ChainNetwork) string {
	switch c {
	case BTCChain:
		switch cn {
		case MainNet:
			return chaincfg.MainNetParams.Bech32HRPSegwit
		case StageNet:
			return chaincfg.MainNetParams.Bech32HRPSegwit
		case MockNet:
			return chaincfg.RegressionNetParams.Bech32HRPSegwit
		case TestNet:
			return chaincfg.TestNet3Params.Bech32HRPSegwit
		}
	case BTCQChain:
		return AccountAddressPrefix
	}
	return ""
}
func (c Chain) IsValidAddress(addr Address) bool {
	network := CurrentChainNetwork
	prefix := c.AddressPrefix(network)
	if !strings.HasPrefix(addr.String(), prefix) {
		return false
	}
	newAddr, err := NewAddress(addr.String())
	if err != nil {
		return false
	}
	return newAddr.Equals(addr)
}

func (c Chain) IsBTCQChain() bool {
	return c.Equals(BTCQChain)
}

func NewChains(raw []string) (Chains, error) {
	var returnErr error
	var chains Chains
	for _, c := range raw {
		chain, err := NewChain(c)
		if err == nil {
			chains = append(chains, chain)
		} else {
			returnErr = multierror.Append(returnErr, err)
		}
	}
	return chains, returnErr
}
func (c Chain) Equals(c2 Chain) bool {
	return strings.EqualFold(c.String(), c2.String())
}

// Has check whether chain c is in the list
func (chains Chains) Has(c Chain) bool {
	for _, ch := range chains {
		if ch.Equals(c) {
			return true
		}
	}
	return false
}

// Distinct return a distinct set of chains, no duplicates
func (chains Chains) Distinct() Chains {
	var newChains Chains
	for _, chain := range chains {
		if !newChains.Has(chain) {
			newChains = append(newChains, chain)
		}
	}
	return newChains
}

func (chains Chains) Strings() []string {
	strChains := make([]string, len(chains))
	for i, c := range chains {
		strChains[i] = c.String()
	}
	return strChains
}
