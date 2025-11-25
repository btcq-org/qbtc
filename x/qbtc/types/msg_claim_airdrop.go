package types

import (
	"encoding/hex"

	se "github.com/cosmos/cosmos-sdk/types/errors"
)

// Hash160Length is the length of a Bitcoin Hash160 (RIPEMD160(SHA256(pubkey)))
const Hash160Length = 20

// ValidateBasic performs basic validation of the MsgClaimAirdrop message.
func (m *MsgClaimAirdrop) ValidateBasic() error {
	if m.Claimer == "" {
		return se.ErrInvalidRequest.Wrap("claimer address is required")
	}

	if len(m.BtcAddressHash) != Hash160Length {
		return se.ErrInvalidRequest.Wrapf("btc_address_hash must be %d bytes (Hash160), got %d", Hash160Length, len(m.BtcAddressHash))
	}

	if len(m.Proof.ProofData) == 0 {
		return se.ErrInvalidRequest.Wrap("proof data is required")
	}

	return nil
}

// BtcAddressHashHex returns the hex-encoded Bitcoin address hash.
func (m *MsgClaimAirdrop) BtcAddressHashHex() string {
	return hex.EncodeToString(m.BtcAddressHash)
}
