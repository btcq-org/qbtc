package types

import (
	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/cosmos/cosmos-sdk/types/errors"
)

var _ sdk.Msg = &MsgBtcBlock{}

func (m *MsgBtcBlock) ValidateBasic() error {
	if len(m.Hash) == 0 {
		return errors.ErrInvalidRequest.Wrap("block hash cannot be empty")
	}

	if len(m.Signer) == 0 {
		return errors.ErrInvalidRequest.Wrap("signer cannot be empty")
	}

	_, err := sdk.AccAddressFromBech32(m.Signer)
	if err != nil {
		return errors.ErrInvalidAddress.Wrapf("invalid signer address: %s", err)
	}

	if len(m.BlockContent) == 0 {
		return errors.ErrInvalidRequest.Wrap("block content cannot be empty")
	}

	if len(m.Attestations) == 0 {
		return errors.ErrInvalidRequest.Wrap("attestations cannot be empty")
	}
	return nil
}
func (m *MsgBtcBlock) GetSigners() []sdk.AccAddress {
	creator, err := sdk.AccAddressFromBech32(m.Signer)
	if err != nil {
		panic(err)
	}
	return []sdk.AccAddress{creator}
}
