package types

import (
	sdk "github.com/cosmos/cosmos-sdk/types"
	se "github.com/cosmos/cosmos-sdk/types/errors"
)

var (
	_ sdk.Msg              = &MsgBond{}
	_ sdk.HasValidateBasic = &MsgBond{}
	_ sdk.Msg              = &MsgUnbond{}
	_ sdk.HasValidateBasic = &MsgUnbond{}
)

func (m *MsgBond) ValidateBasic() error {
	if _, err := sdk.AccAddressFromBech32(m.Signer); err != nil {
		return se.ErrInvalidAddress.Wrapf("signer: %v", err)
	}
	if _, err := sdk.AccAddressFromBech32(m.NodeId); err != nil {
		return se.ErrInvalidAddress.Wrapf("node_id: %v", err)
	}
	if m.Units.IsZero() {
		return se.ErrInvalidRequest.Wrap("units must be non-zero")
	}
	return nil
}

func (m *MsgUnbond) ValidateBasic() error {
	if _, err := sdk.AccAddressFromBech32(m.Signer); err != nil {
		return se.ErrInvalidAddress.Wrapf("signer: %v", err)
	}
	if _, err := sdk.AccAddressFromBech32(m.NodeId); err != nil {
		return se.ErrInvalidAddress.Wrapf("node_id: %v", err)
	}
	if m.Units.IsZero() {
		return se.ErrInvalidRequest.Wrap("units must be non-zero")
	}
	return nil
}
