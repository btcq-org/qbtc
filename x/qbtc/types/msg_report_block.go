package types

import (
	"bytes"

	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/cosmos/cosmos-sdk/types/errors"
)

var _ sdk.Msg = &MsgBtcBlock{}

// EBifrostSignerAddress is the signer of every MsgBtcBlock that the block
// proposer injects. It is the truncated SHA-256 of "ebifrost_signer", not the
// address of any public key, so no one can sign for it. The block handler
// rejects MsgBtcBlock with any other signer, which keeps the message off every
// path where a user picks the signer (a normal tx, authz MsgExec, wasm, ICA).
const EBifrostSignerAddress = "qbtc102aqxl4u8h9q4lcsruq56kkmeey0v699phhvuv"

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

func (m *MsgBtcBlock) GetAttestations() []*Attestation {
	return m.Attestations
}

func (m *MsgBtcBlock) SetAttestations(attestations []*Attestation) *MsgBtcBlock {
	m.Attestations = attestations
	return m
}

func (m *MsgBtcBlock) RemoveAttestations(attestations []*Attestation) bool {
	m.Attestations = removeAttestations(m.Attestations, attestations)
	return len(m.Attestations) == 0
}
func (m *MsgBtcBlock) Equals(other *MsgBtcBlock) bool {
	return m.Height == other.Height && m.Hash == other.Hash
}

func (a *Attestation) Equals(other *Attestation) bool {
	if a == nil || other == nil {
		return a == other
	}
	return a.Address == other.Address && bytes.Equal(a.Signature, other.Signature)
}
