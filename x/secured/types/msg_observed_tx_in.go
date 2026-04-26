package types

import (
	"strconv"

	sdk "github.com/cosmos/cosmos-sdk/types"
	se "github.com/cosmos/cosmos-sdk/types/errors"
)

var (
	_ sdk.Msg              = &MsgObservedTxIn{}
	_ sdk.HasValidateBasic = &MsgObservedTxIn{}
)

const (
	MaxTxIDLength = 64
	MaxMemoLength = 80 // Bitcoin OP_RETURN cap
)

func (m *MsgObservedTxIn) ValidateBasic() error {
	if _, err := sdk.AccAddressFromBech32(m.Signer); err != nil {
		return se.ErrInvalidAddress.Wrapf("signer: %v", err)
	}
	if len(m.Observations) == 0 {
		return se.ErrInvalidRequest.Wrap("observations is empty")
	}
	if len(m.Attestations) == 0 {
		return se.ErrInvalidRequest.Wrap("attestations is empty")
	}
	seen := make(map[string]bool, len(m.Observations))
	for i, o := range m.Observations {
		if len(o.Txid) != MaxTxIDLength {
			return se.ErrInvalidRequest.Wrapf("observations[%d]: txid must be %d hex chars", i, MaxTxIDLength)
		}
		if o.AmountSats.IsZero() {
			return se.ErrInvalidRequest.Wrapf("observations[%d]: amount_sats is zero", i)
		}
		if o.BtcRecipient == "" {
			return se.ErrInvalidRequest.Wrapf("observations[%d]: btc_recipient is required", i)
		}
		if len(o.Memo) > MaxMemoLength {
			return se.ErrInvalidRequest.Wrapf("observations[%d]: memo exceeds %d bytes", i, MaxMemoLength)
		}
		key := o.Txid + ":" + strconv.FormatUint(uint64(o.Vout), 10)
		if seen[key] {
			return se.ErrInvalidRequest.Wrapf("observations[%d]: duplicate %s", i, key)
		}
		seen[key] = true
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
