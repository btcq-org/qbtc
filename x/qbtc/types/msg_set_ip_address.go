package types

import (
	"net"

	sdk "github.com/cosmos/cosmos-sdk/types"
	se "github.com/cosmos/cosmos-sdk/types/errors"
)

var (
	_ sdk.Msg              = &MsgSetIPAddress{}
	_ sdk.HasValidateBasic = &MsgSetIPAddress{}
	_ sdk.LegacyMsg        = &MsgSetIPAddress{}
)

// NewMsgSetIPAddress creates a new MsgSetIPAddress instance
func NewMsgSetIPAddress(ip string, nodeAddress sdk.AccAddress) *MsgSetIPAddress {
	return &MsgSetIPAddress{
		Signer:    nodeAddress.String(),
		IPAddress: ip,
	}
}

// ValidateBasic implements HasValidateBasic
func (m *MsgSetIPAddress) ValidateBasic() error {
	if m.Signer == "" {
		return se.ErrInvalidAddress.Wrap("signer cannot be empty")
	}

	_, err := sdk.AccAddressFromBech32(m.Signer)
	if err != nil {
		return se.ErrInvalidAddress.Wrap(err.Error())
	}

	if net.ParseIP(m.IPAddress) == nil {
		return se.ErrUnknownRequest.Wrap("invalid IP address")
	}
	return nil
}

// GetSigners defines whose signature is required
func (m *MsgSetIPAddress) GetSigners() []sdk.AccAddress {
	acct, _ := sdk.AccAddressFromBech32(m.Signer)
	return []sdk.AccAddress{acct}
}
