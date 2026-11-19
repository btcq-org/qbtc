package types

import (
	"fmt"

	"github.com/btcq-org/qbtc/constants"
	sdk "github.com/cosmos/cosmos-sdk/types"
	sdkerrors "github.com/cosmos/cosmos-sdk/types/errors"
)

var (
	_ sdk.Msg              = &MsgUpdateParam{}
	_ sdk.HasValidateBasic = &MsgUpdateParam{}
)

func NewMsgUpdateParam(authority string, key string, value int64) *MsgUpdateParam {
	return &MsgUpdateParam{
		Authority: authority,
		Key:       key,
		Value:     value,
	}
}

func NewMsgUpdateStringParam(authority string, key string, value string) *MsgUpdateParam {
	return &MsgUpdateParam{
		Authority:   authority,
		Key:         key,
		StringValue: value,
	}
}

func isStringParamKey(key string) bool {
	return key == DevFundAddressKey || key == MarketingFundAddressKey
}

// ValidateStringParam checks that key is a string param and value is empty,
// which leaves it unset, or a valid account address.
func ValidateStringParam(key, value string) error {
	if !isStringParamKey(key) {
		return fmt.Errorf("unknown string param %q", key)
	}
	if value == "" {
		return nil
	}
	if _, err := sdk.AccAddressFromBech32(value); err != nil {
		return fmt.Errorf("string param %s: invalid address: %w", key, err)
	}
	return nil
}

func (m *MsgUpdateParam) ValidateBasic() error {
	if m.Authority == "" {
		return sdkerrors.ErrInvalidAddress.Wrap("authority cannot be empty")
	}
	if m.Key == "" {
		return sdkerrors.ErrUnknownRequest.Wrap("parameter key cannot be empty")
	}

	if isStringParamKey(m.Key) {
		if m.StringValue != "" {
			if _, err := sdk.AccAddressFromBech32(m.StringValue); err != nil {
				return sdkerrors.ErrInvalidAddress.Wrapf("invalid address for %s: %s", m.Key, err)
			}
		}
		return nil
	}

	if _, ok := constants.FromString(m.Key); !ok {
		return sdkerrors.ErrUnknownRequest.Wrapf("unknown parameter key: %s", m.Key)
	}
	if m.Value < 0 {
		return sdkerrors.ErrUnknownRequest.Wrap("parameter value cannot be negative")
	}
	return nil
}
