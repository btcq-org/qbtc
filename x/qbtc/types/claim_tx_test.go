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

func TestFreeClaimGasLimit(t *testing.T) {
	require.Equal(t, types.FreeClaimBaseGas, types.FreeClaimGasLimit(1))
	require.Equal(t, uint64(500_000), types.FreeClaimGasLimit(2))
	require.Equal(t, uint64(2_900_000), types.FreeClaimGasLimit(types.MaxBatchClaimUTXOs))
	require.Equal(t, types.FreeClaimMaxGas, types.FreeClaimGasLimit(types.MaxBatchClaimUTXOs))
	// ValidateBasic rejects these; the limit stays in range anyway.
	require.Equal(t, types.FreeClaimBaseGas, types.FreeClaimGasLimit(0))
	require.Equal(t, types.FreeClaimMaxGas, types.FreeClaimGasLimit(types.MaxBatchClaimUTXOs+1))
}

func TestFreeClaimTxGasLimit(t *testing.T) {
	claim := &types.MsgClaimWithProof{Utxos: make([]types.UTXORef, 3)}
	require.Equal(t, uint64(550_000), types.FreeClaimTxGasLimit(msgsTx{msgs: []sdk.Msg{claim}}))
	require.Equal(t, types.FreeClaimMaxGas, types.FreeClaimTxGasLimit(msgsTx{msgs: []sdk.Msg{claim, claim}}))
}

func TestIsClaimOnlyTx(t *testing.T) {
	claim := &types.MsgClaimWithProof{}
	require.True(t, types.IsClaimOnlyTx(msgsTx{msgs: []sdk.Msg{claim}}))
	require.True(t, types.IsClaimOnlyTx(msgsTx{msgs: []sdk.Msg{claim, claim}}))
	require.False(t, types.IsClaimOnlyTx(msgsTx{}))
	require.False(t, types.IsClaimOnlyTx(msgsTx{msgs: []sdk.Msg{claim, &types.MsgEmpty{}}}))
	exec := authz.NewMsgExec(sdk.AccAddress("grantee"), []sdk.Msg{claim})
	require.False(t, types.IsClaimOnlyTx(msgsTx{msgs: []sdk.Msg{&exec}}))
}

func TestCountClaimMsgs(t *testing.T) {
	claim := &types.MsgClaimWithProof{}
	inner := authz.NewMsgExec(sdk.AccAddress("grantee"), []sdk.Msg{claim, &types.MsgEmpty{}})
	outer := authz.NewMsgExec(sdk.AccAddress("grantee"), []sdk.Msg{&inner, claim})
	require.Equal(t, 0, types.CountClaimMsgs(nil))
	require.Equal(t, 1, types.CountClaimMsgs([]sdk.Msg{claim, &types.MsgEmpty{}}))
	require.Equal(t, 1, types.CountClaimMsgs([]sdk.Msg{&inner}))
	require.Equal(t, 3, types.CountClaimMsgs([]sdk.Msg{claim, &outer}))
}
