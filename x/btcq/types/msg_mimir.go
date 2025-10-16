package types

import (
	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/cosmos/cosmos-sdk/types/errors"
)

var (
	_ sdk.Msg              = &MsgMimir{}
	_ sdk.HasValidateBasic = &MsgMimir{}
	_ sdk.LegacyMsg        = &MsgMimir{}
)

// ValidateBasic implements HasValidateBasic
// ValidateBasic is now ran in the message service router handler for messages that
// used to be routed using the external handler and only when HasValidateBasic is implemented.
// No versioning is used there.
func (m *MsgMimir) ValidateBasic() error {
	if m.Key == "" {
		return errors.ErrUnknownRequest
	}

	if m.Signer == "" {
		return errors.ErrInvalidAddress
	}
	_, err := sdk.AccAddressFromBech32(m.Signer)
	if err != nil {
		return errors.ErrInvalidAddress.Wrap(err.Error())
	}
	return nil
}

// GetSigners defines whose signature is required
func (m *MsgMimir) GetSigners() []sdk.AccAddress {
	acct, _ := sdk.AccAddressFromBech32(m.Signer)
	return []sdk.AccAddress{acct}
}
