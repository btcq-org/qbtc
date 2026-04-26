package types

import (
	sdk "github.com/cosmos/cosmos-sdk/types"
	se "github.com/cosmos/cosmos-sdk/types/errors"
)

var (
	_ sdk.Msg              = &MsgUpdateParam{}
	_ sdk.HasValidateBasic = &MsgUpdateParam{}
)

func NewMsgUpdateParam(authority, key string, value int64) *MsgUpdateParam {
	return &MsgUpdateParam{Authority: authority, Key: key, Value: value}
}

func (m *MsgUpdateParam) ValidateBasic() error {
	if m.Authority == "" {
		return se.ErrInvalidAddress.Wrap("authority cannot be empty")
	}
	if m.Key == "" {
		return se.ErrUnknownRequest.Wrap("parameter key cannot be empty")
	}
	if !IsKnownParam(m.Key) {
		return ErrUnknownParam.Wrap(m.Key)
	}
	if m.Value < 0 {
		return se.ErrUnknownRequest.Wrap("parameter value cannot be negative")
	}
	return nil
}
