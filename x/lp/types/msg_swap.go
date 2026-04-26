package types

import (
	sdk "github.com/cosmos/cosmos-sdk/types"
	se "github.com/cosmos/cosmos-sdk/types/errors"
)

var (
	_ sdk.Msg              = &MsgSwap{}
	_ sdk.HasValidateBasic = &MsgSwap{}
)

// Native qbtc denom mirrors sdk.DefaultBondDenom set in app/config.go.
const DenomQbtc = "qbtc"

func (m *MsgSwap) ValidateBasic() error {
	if _, err := sdk.AccAddressFromBech32(m.Signer); err != nil {
		return se.ErrInvalidAddress.Wrapf("signer: %v", err)
	}
	if m.Amount.IsZero() {
		return se.ErrInvalidRequest.Wrap("amount must be non-zero")
	}
	if m.DestAddress == "" {
		return se.ErrInvalidRequest.Wrap("dest_address is required")
	}
	if !isLegalSwapPair(m.SourceDenom, m.DestDenom) {
		return ErrInvalidPair.Wrapf("%s -> %s", m.SourceDenom, m.DestDenom)
	}
	return nil
}

// isLegalSwapPair enforces the three on-chain pairs handled by MsgSwap. The
// fourth pair (BTC L1 -> qbtc) is memo-driven via MsgObservedTxIn.
func isLegalSwapPair(src, dst string) bool {
	switch {
	case src == DenomQbtc && dst == DenomSecuredBTC:
		return true
	case src == DenomQbtc && dst == "btc":
		return true
	case src == DenomSecuredBTC && dst == DenomQbtc:
		return true
	}
	return false
}
