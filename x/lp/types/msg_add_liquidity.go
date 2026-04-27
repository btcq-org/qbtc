package types

import (
	sdk "github.com/cosmos/cosmos-sdk/types"
	se "github.com/cosmos/cosmos-sdk/types/errors"
)

var (
	_ sdk.Msg              = &MsgAddLiquidity{}
	_ sdk.HasValidateBasic = &MsgAddLiquidity{}
)

func (m *MsgAddLiquidity) ValidateBasic() error {
	if _, err := sdk.AccAddressFromBech32(m.Signer); err != nil {
		return se.ErrInvalidAddress.Wrapf("signer: %v", err)
	}
	if _, err := sdk.AccAddressFromBech32(m.NodeId); err != nil {
		return se.ErrInvalidAddress.Wrapf("node_id: %v", err)
	}
	if m.QbtcAmount.IsZero() {
		return se.ErrInvalidRequest.Wrap("qbtc_amount must be non-zero")
	}
	if m.BtcAmountDeclared.IsZero() {
		return se.ErrInvalidRequest.Wrap("btc_amount_declared must be non-zero")
	}
	if m.BtcAddress == "" {
		return se.ErrInvalidRequest.Wrap("btc_address is required")
	}
	return nil
}
