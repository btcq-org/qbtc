package types

import (
	sdk "github.com/cosmos/cosmos-sdk/types"
	se "github.com/cosmos/cosmos-sdk/types/errors"
)

var (
	_ sdk.Msg              = &MsgWithdrawLiquidity{}
	_ sdk.HasValidateBasic = &MsgWithdrawLiquidity{}
)

func (m *MsgWithdrawLiquidity) ValidateBasic() error {
	if _, err := sdk.AccAddressFromBech32(m.Signer); err != nil {
		return se.ErrInvalidAddress.Wrapf("signer: %v", err)
	}
	if _, err := sdk.AccAddressFromBech32(m.NodeId); err != nil {
		return se.ErrInvalidAddress.Wrapf("node_id: %v", err)
	}
	if m.BasisPoints == 0 || m.BasisPoints > uint32(BasisPointsDenom) {
		return ErrInvalidBasisPoints
	}
	return nil
}
