package types

import (
	"crypto/sha256"
	"encoding/hex"

	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/cosmos/cosmos-sdk/types/errors"
)

var _ sdk.Msg = &MsgInjectBtcBlock{}

// Digest returns the canonical sha256 digest of the marshaled delta. It is the
// value attested in vote extensions (BtcBlockAttest.DeltaHash). gogoproto
// marshaling is deterministic for a fixed set of field values, so honest
// observers that construct identical deltas produce identical digests.
func (d *BtcBlockDelta) Digest() []byte {
	if d == nil {
		return nil
	}
	bz, err := d.Marshal()
	if err != nil {
		// Marshal of a generated message with no maps cannot fail in practice.
		panic(err)
	}
	sum := sha256.Sum256(bz)
	return sum[:]
}

// TxidHex returns the display-order hex of the spent outpoint's txid.
func (o *BtcOutpoint) TxidHex() string { return hex.EncodeToString(o.Txid) }

// TxidHex returns the display-order hex of the transaction id.
func (t *BtcTx) TxidHex() string { return hex.EncodeToString(t.Txid) }

func (m *MsgInjectBtcBlock) ValidateBasic() error {
	if m.Delta == nil {
		return errors.ErrInvalidRequest.Wrap("delta cannot be nil")
	}
	if len(m.Delta.BlockHash) == 0 {
		return errors.ErrInvalidRequest.Wrap("block hash cannot be empty")
	}
	if len(m.ExtendedCommitInfo) == 0 {
		return errors.ErrInvalidRequest.Wrap("extended commit info cannot be empty")
	}
	if len(m.Signer) == 0 {
		return errors.ErrInvalidRequest.Wrap("signer cannot be empty")
	}
	if _, err := sdk.AccAddressFromBech32(m.Signer); err != nil {
		return errors.ErrInvalidAddress.Wrapf("invalid signer address: %s", err)
	}
	return nil
}

func (m *MsgInjectBtcBlock) GetSigners() []sdk.AccAddress {
	signer, err := sdk.AccAddressFromBech32(m.Signer)
	if err != nil {
		panic(err)
	}
	return []sdk.AccAddress{signer}
}
