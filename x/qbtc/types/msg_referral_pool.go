package types

import (
	se "github.com/cosmos/cosmos-sdk/types/errors"
)

func (m *MsgFundReferralPool) ValidateBasic() error {
	return validateReferralPoolMove(m.Authority, m.Amount)
}

func (m *MsgDrainReferralPool) ValidateBasic() error {
	return validateReferralPoolMove(m.Authority, m.Amount)
}

// validateReferralPoolMove checks the message shape. The handler checks the
// authority is the governance account.
func validateReferralPoolMove(authority string, amount uint64) error {
	if authority == "" {
		return se.ErrInvalidRequest.Wrap("authority is required")
	}
	if amount == 0 {
		return se.ErrInvalidRequest.Wrap("amount must be positive")
	}
	// Amounts become int64 coins.
	if amount > uint64(1<<63-1) {
		return se.ErrInvalidRequest.Wrap("amount is too large")
	}
	return nil
}
