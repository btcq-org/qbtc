package abci

import (
	"math"
	"testing"

	abci "github.com/cometbft/cometbft/abci/types"
	cmtproto "github.com/cometbft/cometbft/proto/tendermint/types"
	"github.com/cosmos/cosmos-sdk/baseapp"
	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/cosmos/cosmos-sdk/types/mempool"
	"github.com/cosmos/cosmos-sdk/x/authz"
	"github.com/stretchr/testify/require"

	"github.com/btcq-org/qbtc/constants"
	"github.com/btcq-org/qbtc/x/qbtc/types"
)

// gasTx is a regular transaction that declares a gas limit.
type gasTx struct {
	plainTx
	gas uint64
}

func (t gasTx) GetGas() uint64 { return t.gas }

func claimTx(declaredGas uint64) sdk.Tx {
	return gasTx{plainTx: plainTx{msgs: []sdk.Msg{&types.MsgClaimWithProof{}}}, gas: declaredGas}
}

func claimTxs(n int) []sdk.Tx {
	txs := make([]sdk.Tx, n)
	for i := range txs {
		txs[i] = claimTx(0)
	}
	return txs
}

// withMaxGas sets the consensus block.max_gas of ctx, keeping its other params.
func withMaxGas(ctx sdk.Context, maxGas int64) sdk.Context {
	cp := ctx.ConsensusParams()
	cp.Block = &cmtproto.BlockParams{MaxGas: maxGas}
	return ctx.WithConsensusParams(cp)
}

func TestProcessProposalBlockLimits(t *testing.T) {
	const accept, reject = abci.ResponseProcessProposal_ACCEPT, abci.ResponseProcessProposal_REJECT
	f := newFixture(t, 6, 40, 30, 30)
	ctx := f.ctxWith(f.commit())
	maxClaims := int(constants.DefaultValues[constants.MaxClaimsPerBlock])
	require.Equal(t, 200, maxClaims)

	t.Run("claims up to the cap", func(t *testing.T) {
		require.Equal(t, accept, f.process(ctx, claimTxs(maxClaims)...))
	})

	t.Run("one claim over the cap", func(t *testing.T) {
		require.Equal(t, reject, f.process(ctx, claimTxs(maxClaims+1)...))
	})

	t.Run("claims nested in MsgExec count", func(t *testing.T) {
		exec := authz.NewMsgExec(sdk.AccAddress("grantee"), []sdk.Msg{&types.MsgClaimWithProof{}, &types.MsgClaimWithProof{}})
		txs := append(claimTxs(maxClaims-1), gasTx{plainTx: plainTx{msgs: []sdk.Msg{&exec}}})
		require.Equal(t, reject, f.process(ctx, txs...))
		require.Equal(t, accept, f.process(ctx, txs[1:]...))
	})

	t.Run("governance lowers the cap", func(t *testing.T) {
		ctx, _ := ctx.CacheContext()
		require.NoError(t, f.keeper.ConstOverrides.Set(ctx, constants.MaxClaimsPerBlock.String(), 2))
		require.Equal(t, accept, f.process(ctx, claimTxs(2)...))
		require.Equal(t, reject, f.process(ctx, claimTxs(3)...))
	})

	t.Run("declared gas over max_gas", func(t *testing.T) {
		ctx := withMaxGas(ctx, 1_000_000)
		send := func(gas uint64) sdk.Tx { return gasTx{plainTx: plainTx{msgs: []sdk.Msg{&types.MsgEmpty{}}}, gas: gas} }
		require.Equal(t, accept, f.process(ctx, send(600_000), send(400_000)))
		require.Equal(t, reject, f.process(ctx, send(600_000), send(400_001)))
	})

	t.Run("a free claim counts its clamped gas", func(t *testing.T) {
		// Each claim counts types.FreeClaimMinGas (400,000) whatever it declares below it.
		ctx := withMaxGas(ctx, 1_000_000)
		require.Equal(t, accept, f.process(ctx, claimTx(0), claimTx(1)))
		require.Equal(t, reject, f.process(ctx, claimTx(0), claimTx(1), claimTx(2)))
		// and at most types.FreeClaimMaxGas whatever it declares above it.
		ctx = withMaxGas(ctx, int64(types.FreeClaimMaxGas))
		require.Equal(t, accept, f.process(ctx, claimTx(1<<62)))
	})

	t.Run("declared gas that would wrap the sum", func(t *testing.T) {
		ctx := withMaxGas(ctx, 1_000_000)
		send := func(gas uint64) sdk.Tx { return gasTx{plainTx: plainTx{msgs: []sdk.Msg{&types.MsgEmpty{}}}, gas: gas} }
		// 600,000 + (2^64 - 599,999) wraps to 1 in uint64
		require.Equal(t, reject, f.process(ctx, send(600_000), send(math.MaxUint64-599_998)))
	})

	t.Run("max_gas 0 is a limit, as in CometBFT", func(t *testing.T) {
		ctx := withMaxGas(ctx, 0)
		send := func(gas uint64) sdk.Tx { return gasTx{plainTx: plainTx{msgs: []sdk.Msg{&types.MsgEmpty{}}}, gas: gas} }
		require.Equal(t, accept, f.process(ctx, send(0)))
		require.Equal(t, reject, f.process(ctx, send(1)))
	})

	t.Run("no max_gas", func(t *testing.T) {
		ctx := withMaxGas(ctx, -1)
		tx := gasTx{plainTx: plainTx{msgs: []sdk.Msg{&types.MsgEmpty{}}}, gas: 1 << 62}
		require.Equal(t, accept, f.process(ctx, tx, tx))
	})

	t.Run("injected transactions count against neither limit", func(t *testing.T) {
		valid, ec := f.injectedMsg(101, 102, 103)
		ctx := withMaxGas(f.ctxWith(ec), int64(maxClaims)*int64(types.FreeClaimMinGas))
		txs := append([]sdk.Tx{f.injectTx(valid)}, claimTxs(maxClaims)...)
		require.Equal(t, accept, f.process(ctx, txs...))
	})
}

// PrepareProposal leaves out the transactions past either limit, so its
// proposal passes ProcessProposal.
func TestPrepareProposalBlockLimits(t *testing.T) {
	f := newFixture(t, 6, 40, 30, 30)
	maxClaims := int(constants.DefaultValues[constants.MaxClaimsPerBlock])
	prepare := func(ctx sdk.Context, txs []sdk.Tx) [][]byte {
		t.Helper()
		f.txs = txs
		var mempool [][]byte
		for i := range txs {
			mempool = append(mempool, []byte{byte(i)})
		}
		h := NewProposalHandler(f.keeper, f.reader, f.handler.decoder,
			func(_ sdk.Context, _ *abci.RequestPrepareProposal) (*abci.ResponsePrepareProposal, error) {
				return &abci.ResponsePrepareProposal{Txs: mempool}, nil
			}, f.handler.processProposalHandler)
		resp, err := h.PrepareProposal(ctx, &abci.RequestPrepareProposal{MaxTxBytes: 10 << 20, Height: testHeight})
		require.NoError(t, err)
		return resp.Txs
	}

	t.Run("claims past the cap", func(t *testing.T) {
		ctx := f.ctxWith(f.commit())
		kept := prepare(ctx, claimTxs(maxClaims+5))
		require.Len(t, kept, maxClaims)
		require.Equal(t, abci.ResponseProcessProposal_ACCEPT, f.process(ctx, f.txs[:maxClaims]...))
	})

	t.Run("a transaction past max_gas", func(t *testing.T) {
		ctx := withMaxGas(f.ctxWith(f.commit()), 1_000_000)
		big := gasTx{plainTx: plainTx{msgs: []sdk.Msg{&types.MsgEmpty{}}}, gas: 700_000}
		small := gasTx{plainTx: plainTx{msgs: []sdk.Msg{&types.MsgEmpty{}}}, gas: 300_000}
		// the second big one does not fit, the small one after it does
		kept := prepare(ctx, []sdk.Tx{big, big, small})
		require.Equal(t, [][]byte{{0}, {2}}, kept)
	})
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

// The SDK's default PrepareProposal, which runs before the proposal checks,
// must count a free claim at its clamped gas too. CheckTx admits a claim
// declaring up to max_gas.
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
	// Counted at types.FreeClaimMaxGas, the claim leaves room for the rest.
	require.Equal(t, [][]byte{{0}, {1}, {2}}, prepare(NewTxSelector()))
}
