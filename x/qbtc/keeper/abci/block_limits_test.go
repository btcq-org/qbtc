package abci

import (
	"fmt"
	"math"
	"testing"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"

	abci "github.com/cometbft/cometbft/abci/types"
	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/cosmos/cosmos-sdk/x/authz"
	"github.com/stretchr/testify/require"

	"github.com/btcq-org/qbtc/constants"
	"github.com/btcq-org/qbtc/x/qbtc/keeper"
	"github.com/btcq-org/qbtc/x/qbtc/types"
)

func claimTxs(n int) []sdk.Tx {
	txs := make([]sdk.Tx, n)
	for i := range txs {
		txs[i] = claimTx(0)
	}
	return txs
}

// claimFor is a free claim of the given UTXOs.
func claimFor(refs ...types.UTXORef) sdk.Tx {
	return gasTx{plainTx: plainTx{msgs: []sdk.Msg{&types.MsgClaimWithProof{Utxos: refs}}}}
}

// seedUTXO stores an unclaimed UTXO, number i, at the P2WPKH address of
// holder, and returns a reference to it.
func seedUTXO(t *testing.T, ctx sdk.Context, k *keeper.Keeper, i int, holder byte) types.UTXORef {
	t.Helper()
	hash := make([]byte, 20)
	hash[0] = holder
	addr, err := btcutil.NewAddressWitnessPubKeyHash(hash, &chaincfg.MainNetParams)
	require.NoError(t, err)
	utxo := types.UTXO{
		Txid:           fmt.Sprintf("%064x", i),
		Amount:         1_000,
		EntitledAmount: 1_000,
		ScriptPubKey:   &types.ScriptPubKeyResult{Address: addr.EncodeAddress()},
	}
	require.NoError(t, k.Utxoes.Set(ctx, utxo.GetKey(), utxo))
	return types.UTXORef{Txid: utxo.Txid}
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

	t.Run("a free claim counts the gas computed from its UTXOs", func(t *testing.T) {
		// types.FreeClaimBaseGas (450,000) for one UTXO, whatever it declares
		ctx := withMaxGas(ctx, 1_000_000)
		require.Equal(t, accept, f.process(ctx, claimTx(0), claimTx(1<<62)))
		require.Equal(t, reject, f.process(ctx, claimTx(0), claimTx(0), claimTx(0)))
		// and types.FreeClaimMaxGas for a full batch
		full := gasTx{plainTx: plainTx{msgs: []sdk.Msg{&types.MsgClaimWithProof{Utxos: make([]types.UTXORef, types.MaxBatchClaimUTXOs)}}}}
		require.Equal(t, accept, f.process(withMaxGas(ctx, int64(types.FreeClaimMaxGas)), full))
		require.Equal(t, reject, f.process(withMaxGas(ctx, int64(types.FreeClaimMaxGas)-1), full))
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
		ctx := withMaxGas(f.ctxWith(ec), int64(maxClaims)*int64(types.FreeClaimBaseGas))
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
		// each claim of its own holder's UTXO
		claims := make([]sdk.Tx, maxClaims+5)
		for i := range claims {
			claims[i] = claimFor(seedUTXO(t, ctx, f.keeper, 1000+i, byte(i)))
		}
		kept := prepare(ctx, claims)
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

// PrepareProposal keeps one free claim per Bitcoin address, the address its
// proof covers, and leaves out a claim that can no longer succeed.
func TestPrepareProposalOneClaimPerAddress(t *testing.T) {
	f := newFixture(t, 6, 40, 30, 30)
	ctx := f.ctxWith(f.commit())
	prepare := func(ctx sdk.Context, txs ...sdk.Tx) [][]byte {
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
	a1 := seedUTXO(t, ctx, f.keeper, 1, 'a')
	a2 := seedUTXO(t, ctx, f.keeper, 2, 'a')
	b1 := seedUTXO(t, ctx, f.keeper, 3, 'b')
	send := gasTx{plainTx: plainTx{msgs: []sdk.Msg{&types.MsgEmpty{}}}}

	t.Run("copies of one claim", func(t *testing.T) {
		require.Equal(t, [][]byte{{0}, {2}, {3}}, prepare(ctx, claimFor(a1), claimFor(a1), claimFor(b1), send))
		// Proposals are not checked for this.
		require.Equal(t, abci.ResponseProcessProposal_ACCEPT, f.process(ctx, f.txs...))
	})

	t.Run("two claims of one address", func(t *testing.T) {
		// The second waits for a later block.
		require.Equal(t, [][]byte{{0}}, prepare(ctx, claimFor(a1), claimFor(a2)))
	})

	t.Run("a claim that lists another holder's UTXO after its own", func(t *testing.T) {
		// It covers a's address only, so b's claim stays.
		require.Equal(t, [][]byte{{0}, {1}}, prepare(ctx, claimFor(a1, b1), claimFor(b1)))
	})

	t.Run("a claim of claimed UTXOs", func(t *testing.T) {
		ctx, _ := ctx.CacheContext()
		utxo, err := f.keeper.Utxoes.Get(ctx, fmt.Sprintf("%s-%d", a1.Txid, a1.Vout))
		require.NoError(t, err)
		utxo.EntitledAmount = 0
		require.NoError(t, f.keeper.Utxoes.Set(ctx, utxo.GetKey(), utxo))
		require.Equal(t, [][]byte{{1}}, prepare(ctx, claimFor(a1), claimFor(b1)))
	})
}
