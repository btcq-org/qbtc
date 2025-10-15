package common

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"

	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/cosmos/gogoproto/jsonpb"
)

var (
	EmptyAsset = Asset{Chain: "", Symbol: "", Ticker: "", Secured: false}
	BTCQAsset  = Asset{Chain: "BTCQ", Symbol: "BTCQ", Ticker: "BTCQ", Secured: false}
	BTCAsset   = Asset{Chain: "BTC", Symbol: "BTC", Ticker: "BTC", Secured: false}
)
var _ sdk.CustomProtobufType = (*Asset)(nil)

func NewAsset(input string) (Asset, error) {
	var err error
	var asset Asset
	var sym string
	var parts []string
	re := regexp.MustCompile("[.-]")

	match := re.FindString(input)

	switch match {
	case "-":
		parts = strings.SplitN(input, match, 2)
		asset.Secured = true
	case ".":
		parts = strings.SplitN(input, match, 2)
	case "":
		parts = []string{input}
	}
	if len(parts) == 1 {
		asset.Chain = BTCQChain
		sym = parts[0]
	} else {
		asset.Chain, err = NewChain(parts[0])
		if err != nil {
			return EmptyAsset, err
		}
		sym = parts[1]
	}

	asset.Symbol, err = NewSymbol(sym)
	if err != nil {
		return EmptyAsset, err
	}

	parts = strings.SplitN(sym, "-", 2)
	asset.Ticker, err = NewTicker(parts[0])
	if err != nil {
		return EmptyAsset, err
	}

	return asset, nil
}

func (a Asset) Valid() error {
	if err := a.Chain.Valid(); err != nil {
		return fmt.Errorf("invalid chain: %w", err)
	}
	if err := a.Symbol.Valid(); err != nil {
		return fmt.Errorf("invalid symbol: %w", err)
	}

	if a.Secured && !a.Chain.IsBTCQChain() {
		return fmt.Errorf("secured asset cannot have chain: %s", a)
	}
	return nil
}

// String implement fmt.Stringer , return the string representation of Asset
func (a Asset) String() string {
	div := "."
	if a.Secured {
		div = "-"
	}
	return fmt.Sprintf("%s%s%s", a.Chain.String(), div, a.Symbol.String())
}

// Equals determinate whether two assets are equivalent
func (a Asset) Equals(a2 Asset) bool {
	return a.Chain.Equals(a2.Chain) && a.Symbol.Equals(a2.Symbol) && a.Ticker.Equals(a2.Ticker) && a.Secured == a2.Secured
}

// GetChain return the actual chain of the asset
func (a Asset) GetChain() Chain {
	if a.Secured {
		return BTCQChain
	}
	return a.Chain
}

// IsSecuredAsset return true if the asset is a secured asset
func (a Asset) IsSecuredAsset() bool {
	return a.Secured
}

// GetSecuredAsset return the secured version of the asset
func (a Asset) GetSecuredAsset() Asset {
	if a.IsSecuredAsset() {
		return a
	}
	return Asset{
		Chain:   a.Chain,
		Symbol:  a.Symbol,
		Ticker:  a.Ticker,
		Secured: true,
	}
}

func (a Asset) Native() string {
	if a.Equals(BTCQAsset) {
		return "btcq"
	}
	return strings.ToLower(a.String())
}

// IsNative is a helper function, returns true when the asset is a native
func (a Asset) IsNative() bool {
	return a.GetChain().IsBTCQChain()
}

// MarshalJSON implement Marshaler interface
func (a Asset) MarshalJSON() ([]byte, error) {
	return json.Marshal(a.String())
}

// UnmarshalJSON implement Unmarshaler interface
func (a *Asset) UnmarshalJSON(data []byte) error {
	var err error
	var assetStr string
	if err = json.Unmarshal(data, &assetStr); err != nil {
		return err
	}
	if assetStr == "." {
		*a = EmptyAsset
		return nil
	}
	*a, err = NewAsset(assetStr)
	return err
}

// MarshalJSONPB implement jsonpb.Marshaler
func (a Asset) MarshalJSONPB(*jsonpb.Marshaler) ([]byte, error) {
	return a.MarshalJSON()
}

// UnmarshalJSONPB implement jsonpb.Unmarshaler
func (a *Asset) UnmarshalJSONPB(unmarshal *jsonpb.Unmarshaler, content []byte) error {
	return a.UnmarshalJSON(content)
}

// IsEmpty will be true when any of the field is empty, chain,symbol or ticker
func (a Asset) IsEmpty() bool {
	return a.Chain.IsEmpty() || a.Symbol.IsEmpty() || a.Ticker.IsEmpty()
}
