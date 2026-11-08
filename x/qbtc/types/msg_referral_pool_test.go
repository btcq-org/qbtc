package types

import (
	"testing"

	"github.com/btcq-org/qbtc/common"
	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/stretchr/testify/require"
)

func TestReferralPoolMsgs_ValidateBasic(t *testing.T) {
	sdk.GetConfig().SetBech32PrefixForAccount(common.AccountAddressPrefix, common.AccountAddressPrefix+sdk.PrefixPublic)

	require.NoError(t, (&MsgFundReferralPool{Authority: validBech32Address, Amount: 1}).ValidateBasic())
	require.NoError(t, (&MsgDrainReferralPool{Authority: validBech32Address, Amount: 1}).ValidateBasic())

	require.ErrorContains(t, (&MsgFundReferralPool{Authority: "", Amount: 1}).ValidateBasic(), "authority is required")
	require.ErrorContains(t, (&MsgDrainReferralPool{Authority: validBech32Address}).ValidateBasic(), "amount must be positive")
	require.ErrorContains(t, (&MsgFundReferralPool{Authority: validBech32Address, Amount: 1 << 63}).ValidateBasic(), "too large")
}
