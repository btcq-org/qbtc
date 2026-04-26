package types

import (
	sdk "github.com/cosmos/cosmos-sdk/types"
	se "github.com/cosmos/cosmos-sdk/types/errors"
)

var (
	_ sdk.Msg              = &MsgObservedTxOut{}
	_ sdk.HasValidateBasic = &MsgObservedTxOut{}
)

func (m *MsgObservedTxOut) ValidateBasic() error {
	if _, err := sdk.AccAddressFromBech32(m.Signer); err != nil {
		return se.ErrInvalidAddress.Wrapf("signer: %v", err)
	}
	if m.TxOutId == 0 {
		return se.ErrInvalidRequest.Wrap("tx_out_id is required")
	}
	if len(m.BroadcastTxid) != MaxTxIDLength {
		return se.ErrInvalidRequest.Wrapf("broadcast_txid must be %d hex chars", MaxTxIDLength)
	}
	if len(m.Attestations) == 0 {
		return se.ErrInvalidRequest.Wrap("attestations is empty")
	}
	for i, a := range m.Attestations {
		if a.Address == "" {
			return se.ErrInvalidRequest.Wrapf("attestations[%d]: address is required", i)
		}
		if len(a.Signature) == 0 {
			return se.ErrInvalidRequest.Wrapf("attestations[%d]: signature is required", i)
		}
	}
	return nil
}
