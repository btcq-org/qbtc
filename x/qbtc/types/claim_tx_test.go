package types_test

import (
	"testing"

	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/cosmos/cosmos-sdk/x/authz"
	"github.com/stretchr/testify/require"
	protov2 "google.golang.org/protobuf/proto"

	"github.com/btcq-org/qbtc/x/qbtc/types"
)

type msgsTx struct{ msgs []sdk.Msg }

func (t msgsTx) GetMsgs() []sdk.Msg                    { return t.msgs }
func (t msgsTx) GetMsgsV2() ([]protov2.Message, error) { return nil, nil }

func TestIsClaimOnlyTx(t *testing.T) {
	claim := &types.MsgClaimWithProof{}
	require.True(t, types.IsClaimOnlyTx(msgsTx{msgs: []sdk.Msg{claim}}))
	require.True(t, types.IsClaimOnlyTx(msgsTx{msgs: []sdk.Msg{claim, claim}}))
	require.False(t, types.IsClaimOnlyTx(msgsTx{}))
	require.False(t, types.IsClaimOnlyTx(msgsTx{msgs: []sdk.Msg{claim, &types.MsgEmpty{}}}))
	exec := authz.NewMsgExec(sdk.AccAddress("grantee"), []sdk.Msg{claim})
	require.False(t, types.IsClaimOnlyTx(msgsTx{msgs: []sdk.Msg{&exec}}))
}
