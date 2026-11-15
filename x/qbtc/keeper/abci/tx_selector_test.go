package abci

import (
	"testing"

	abci "github.com/cometbft/cometbft/abci/types"
	cmtproto "github.com/cometbft/cometbft/proto/tendermint/types"
	"github.com/cosmos/cosmos-sdk/baseapp"
	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/cosmos/cosmos-sdk/types/mempool"
	"github.com/stretchr/testify/require"

	"github.com/btcq-org/qbtc/x/qbtc/types"
)

// gasTx is a regular transaction that declares a gas limit.
type gasTx struct {
	plainTx
	gas uint64
}

func (t gasTx) GetGas() uint64 { return t.gas }

// claimTx is a free claim of one UTXO that declares declaredGas.
func claimTx(declaredGas uint64) sdk.Tx {
	return gasTx{plainTx: plainTx{msgs: []sdk.Msg{&types.MsgClaimWithProof{Utxos: make([]types.UTXORef, 1)}}}, gas: declaredGas}
}

// withMaxGas sets the consensus block.max_gas of ctx, keeping its other params.
func withMaxGas(ctx sdk.Context, maxGas int64) sdk.Context {
	cp := ctx.ConsensusParams()
	cp.Block = &cmtproto.BlockParams{MaxGas: maxGas}
	return ctx.WithConsensusParams(cp)
}

// txGas counts a free claim at the gas computed from its UTXOs, whatever it
// declares, and any other transaction at its declared gas.
func TestTxGas(t *testing.T) {
	require.Equal(t, types.FreeClaimBaseGas, txGas(claimTx(0)))
	require.Equal(t, types.FreeClaimBaseGas, txGas(claimTx(1<<62)))
	full := gasTx{plainTx: plainTx{msgs: []sdk.Msg{&types.MsgClaimWithProof{Utxos: make([]types.UTXORef, types.MaxBatchClaimUTXOs)}}}}
	require.Equal(t, types.FreeClaimMaxGas, txGas(full))
	send := gasTx{plainTx: plainTx{msgs: []sdk.Msg{&types.MsgEmpty{}}}, gas: 123_456}
	require.Equal(t, uint64(123_456), txGas(send))
	require.Zero(t, txGas(plainTx{msgs: []sdk.Msg{&types.MsgEmpty{}}}))
}

// fakeVerifier hands the SDK's default proposal handler the transactions of a
// test, indexed by their one-byte encoding.
type fakeVerifier struct{ txs []sdk.Tx }

func (v fakeVerifier) TxDecode(bz []byte) (sdk.Tx, error)           { return v.txs[bz[0]], nil }
func (fakeVerifier) TxEncode(sdk.Tx) ([]byte, error)                { return nil, nil }
func (fakeVerifier) PrepareProposalVerifyTx(sdk.Tx) ([]byte, error) { return nil, nil }
func (fakeVerifier) ProcessProposalVerifyTx([]byte) (sdk.Tx, uint64, error) {
	return nil, 0, nil
}

// The SDK's default PrepareProposal must count a free claim at the gas it runs
// with, not the gas it declares: CheckTx admits a claim declaring up to
// max_gas.
func TestDefaultPrepareProposalCountsClaimGas(t *testing.T) {
	f := newFixture(t, 6, 40, 30, 30)
	ctx := withMaxGas(f.ctx, 10_000_000)
	send := gasTx{plainTx: plainTx{msgs: []sdk.Msg{&types.MsgEmpty{}}}, gas: 1_000_000}
	txs := []sdk.Tx{claimTx(10_000_000), send, send}
	req := &abci.RequestPrepareProposal{MaxTxBytes: 10 << 20, Txs: [][]byte{{0}, {1}, {2}}}

	prepare := func(selector baseapp.TxSelector) [][]byte {
		t.Helper()
		h := baseapp.NewDefaultProposalHandler(mempool.NoOpMempool{}, fakeVerifier{txs: txs})
		if selector != nil {
			h.SetTxSelector(selector)
		}
		resp, err := h.PrepareProposalHandler()(ctx, req)
		require.NoError(t, err)
		return resp.Txs
	}

	// The SDK alone counts the claim's declared 10,000,000 and stops there.
	require.Equal(t, [][]byte{{0}}, prepare(nil))
	// Counted at the gas computed from its UTXOs, the claim leaves room for the rest.
	require.Equal(t, [][]byte{{0}, {1}, {2}}, prepare(NewTxSelector()))
}
