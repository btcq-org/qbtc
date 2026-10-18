package abci

import (
	"testing"

	"github.com/cosmos/cosmos-sdk/codec"
	codectypes "github.com/cosmos/cosmos-sdk/codec/types"
	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/stretchr/testify/require"
	protov2 "google.golang.org/protobuf/proto"

	"github.com/btcq-org/qbtc/x/qbtc/ebifrost"
	"github.com/btcq-org/qbtc/x/qbtc/types"
)

// plainTx is a regular (not injected) transaction.
type plainTx struct{ msgs []sdk.Msg }

func (t plainTx) GetMsgs() []sdk.Msg { return t.msgs }

func (t plainTx) GetMsgsV2() ([]protov2.Message, error) { return nil, nil }

func TestCheckInjectedBlocks(t *testing.T) {
	registry := codectypes.NewInterfaceRegistry()
	types.RegisterInterfaces(registry)
	cdc := codec.NewProtoCodec(registry)
	injected := func(height uint64) sdk.Tx {
		return ebifrost.NewInjectTx(cdc, []sdk.Msg{&types.MsgBtcBlock{Height: height}})
	}

	cases := []struct {
		name          string
		lastProcessed uint64
		txs           []sdk.Tx
		wantErr       string
	}{
		{"consecutive from last processed", 100, []sdk.Tx{injected(101), injected(102)}, ""},
		{"no blocks", 100, nil, ""},
		{"gap", 100, []sdk.Tx{injected(101), injected(103)}, "expected 102"},
		{"old height", 100, []sdk.Tx{injected(99)}, "expected 101"},
		{"repeated height", 100, []sdk.Tx{injected(101), injected(101)}, "expected 102"},
		{"fresh chain starts anywhere", 0, []sdk.Tx{injected(0), injected(1), injected(2)}, ""},
		{"fresh chain, then a gap", 0, []sdk.Tx{injected(0), injected(2)}, "expected 1"},
		{"not injected", 100, []sdk.Tx{plainTx{msgs: []sdk.Msg{&types.MsgBtcBlock{Height: 101}}}}, "not in an inject transaction"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := checkInjectedBlocks(tc.lastProcessed, tc.txs)
			if tc.wantErr == "" {
				require.NoError(t, err)
			} else {
				require.ErrorContains(t, err, tc.wantErr)
			}
		})
	}
}
