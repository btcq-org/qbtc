package types

import (
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

// MaxBtcBlocksPerMsg is the maximum number of Bitcoin blocks one MsgBtcBlock
// carries, so one qbtc block processes at most this many. Validators attest
// more heights than this (MaxBtcBlockVotes): extensions are built on the state
// before the block they vote on, so the next proposer only has attested blocks
// to inject if they reach past the ones that block processes.
const MaxBtcBlocksPerMsg = 8

func (m *MsgBtcBlock) ValidateBasic() error {
	if len(m.Blocks) == 0 {
		return errors.ErrInvalidRequest.Wrap("blocks cannot be empty")
	}
	if len(m.Blocks) > MaxBtcBlocksPerMsg {
		return errors.ErrInvalidRequest.Wrapf("%d blocks, maximum is %d", len(m.Blocks), MaxBtcBlocksPerMsg)
	}
	for i, block := range m.Blocks {
		if block == nil {
			return errors.ErrInvalidRequest.Wrapf("block %d is empty", i)
		}
		if len(block.Hash) == 0 {
			return errors.ErrInvalidRequest.Wrapf("block %d: hash cannot be empty", i)
		}
		if len(block.BlockContent) == 0 {
			return errors.ErrInvalidRequest.Wrapf("block %d: content cannot be empty", i)
		}
	}

	if len(m.ExtendedCommitInfo) == 0 {
		return errors.ErrInvalidRequest.Wrap("extended commit info cannot be empty")
	}

	if len(m.Signer) == 0 {
		return errors.ErrInvalidRequest.Wrap("signer cannot be empty")
	}

	_, err := sdk.AccAddressFromBech32(m.Signer)
	if err != nil {
		return errors.ErrInvalidAddress.Wrapf("invalid signer address: %s", err)
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
