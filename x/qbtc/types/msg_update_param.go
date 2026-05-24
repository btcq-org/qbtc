package types

import (
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
