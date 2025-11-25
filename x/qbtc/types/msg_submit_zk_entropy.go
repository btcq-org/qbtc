package types

import (
	se "github.com/cosmos/cosmos-sdk/types/errors"
)

// EntropyLength is the required length for entropy submissions (32 bytes)
const EntropyLength = 32

// CommitmentLength is the required length for commitment hashes (32 bytes SHA256)
const CommitmentLength = 32

// ValidateBasic performs basic validation of the MsgSubmitZKEntropy message.
func (m *MsgSubmitZKEntropy) ValidateBasic() error {
	if m.Validator == "" {
		return se.ErrInvalidRequest.Wrap("validator address is required")
	}

	if len(m.Entropy) != EntropyLength {
		return se.ErrInvalidRequest.Wrapf(
			"entropy must be exactly %d bytes, got %d",
			EntropyLength, len(m.Entropy),
		)
	}

	if len(m.Commitment) != CommitmentLength {
		return se.ErrInvalidRequest.Wrapf(
			"commitment must be exactly %d bytes, got %d",
			CommitmentLength, len(m.Commitment),
		)
	}

	// Verify entropy is not all zeros (basic sanity check)
	allZeros := true
	for _, b := range m.Entropy {
		if b != 0 {
			allZeros = false
			break
		}
	}
	if allZeros {
		return se.ErrInvalidRequest.Wrap("entropy cannot be all zeros")
	}

	return nil
}

