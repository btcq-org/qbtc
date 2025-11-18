package types

import (
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

func (m *MsgUpdateParam) ValidateBasic() error {
	if m.Authority == "" {
		return sdkerrors.ErrInvalidAddress.Wrap("authority cannot be empty")
	}
	if m.Key == "" {
		return sdkerrors.ErrUnknownRequest.Wrap("parameter key cannot be empty")
	}
	if m.Value < 0 {
		return sdkerrors.ErrUnknownRequest.Wrap("parameter value cannot be negative")
	}
	return nil
}
