package keeper_test

import (
	"encoding/hex"
	"testing"

	storetypes "github.com/cosmos/cosmos-sdk/store/v2/types"
	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/require"
	protov2 "google.golang.org/protobuf/proto"

	"github.com/btcq-org/qbtc/constants"
	"github.com/btcq-org/qbtc/x/qbtc/keeper"
	"github.com/btcq-org/qbtc/x/qbtc/types"
	"github.com/btcq-org/qbtc/x/qbtc/zk"
	"github.com/btcq-org/qbtc/x/qbtc/zk/zktest"
)

type msgsTx struct{ msgs []sdk.Msg }

func (t msgsTx) GetMsgs() []sdk.Msg                    { return t.msgs }
func (t msgsTx) GetMsgsV2() ([]protov2.Message, error) { return nil, nil }

func TestClaimProofDecorator(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	f := setupClaimTest(t)
	const txid = "cccc000000000000000000000000000000000000000000000000000000000001"
	utxo := types.UTXO{
		Txid:           txid,
		Vout:           0,
		Amount:         100_000_000,
		EntitledAmount: 70_000_000,
		ScriptPubKey:   &types.ScriptPubKeyResult{Address: f.btcAddress},
	}
	require.NoError(t, f.keeper.Utxoes.Set(f.ctx, utxo.GetKey(), utxo))

	proof, pubKeyHash := f.generateProof(t)
	valid := &types.MsgClaimWithProof{
		Claimer:          f.claimerAddr,
		Broadcaster:      f.claimerAddr,
		Utxos:            []types.UTXORef{{Txid: txid, Vout: 0}},
		Proof:            hex.EncodeToString(proof),
		PubKeyHashSha256: hex.EncodeToString(pubKeyHash[:]),
	}
	bogus := *valid
	bogus.Proof = hex.EncodeToString(zktest.WellFormedProof(zk.ClaimCircuitNbCommitments))

	decorator := keeper.NewClaimProofDecorator(f.keeper)
	ante := func(ctx sdk.Context, msgs ...sdk.Msg) (sdk.Context, bool, error) {
		t.Helper()
		var nextCtx sdk.Context
		called := false
		_, err := decorator.AnteHandle(ctx, msgsTx{msgs: msgs}, false, func(ctx sdk.Context, _ sdk.Tx, _ bool) (sdk.Context, error) {
			nextCtx, called = ctx, true
			return ctx, nil
		})
		return nextCtx, called, err
	}
	// checkCtx and recheckCtx are fresh copies of the state, as CheckTx and
	// ReCheckTx see it after a commit.
	checkCtx := func() sdk.Context {
		ctx, _ := f.ctx.CacheContext()
		return ctx.WithIsCheckTx(true)
	}
	recheckCtx := func() sdk.Context {
		ctx, _ := f.ctx.CacheContext()
		return ctx.WithIsReCheckTx(true)
	}
	server := keeper.NewMsgServerImpl(f.keeper)

	t.Run("non-claim tx passes through", func(t *testing.T) {
		ctx, _ := f.ctx.CacheContext()
		require.NoError(t, f.keeper.ConstOverrides.Set(ctx, constants.ClaimWithProofDisabled.String(), 1))
		_, called, err := ante(ctx, &types.MsgEmpty{})
		require.NoError(t, err)
		require.True(t, called)
	})

	t.Run("valid claim is verified once, in the ante handler", func(t *testing.T) {
		anteCtx, called, err := ante(f.ctx, valid)
		require.NoError(t, err)
		require.True(t, called)

		f.bankKeeper.EXPECT().MintCoins(gomock.Any(), types.ModuleName, gomock.Any()).Return(nil).Times(2)
		f.bankKeeper.EXPECT().SendCoinsFromModuleToAccount(gomock.Any(), types.ModuleName, gomock.Any(), gomock.Any()).Return(nil).Times(2)
		handlerGas := func(ctx sdk.Context) uint64 {
			t.Helper()
			ctx, _ = ctx.CacheContext()
			ctx = ctx.WithGasMeter(storetypes.NewInfiniteGasMeter())
			resp, err := server.ClaimWithProof(ctx, valid)
			require.NoError(t, err)
			require.Equal(t, uint64(70_000_000), resp.TotalAmountClaimed)
			return ctx.GasMeter().GasConsumed()
		}
		// Same state, with and without the ante handler's record: only the
		// unrecorded run verifies, and pays for it.
		require.Equal(t, keeper.ClaimProofVerifyGas, handlerGas(f.ctx)-handlerGas(anteCtx))
	})

	t.Run("the record covers only the claim that was verified", func(t *testing.T) {
		anteCtx, _, err := ante(f.ctx, valid)
		require.NoError(t, err)
		ctx, _ := anteCtx.CacheContext()
		_, err = server.ClaimWithProof(ctx, &bogus)
		require.ErrorContains(t, err, "proof verification failed")
	})

	t.Run("invalid proof is rejected in CheckTx", func(t *testing.T) {
		_, called, err := ante(checkCtx(), &bogus)
		require.ErrorContains(t, err, "proof verification failed")
		require.False(t, called)
	})

	t.Run("ReCheckTx skips the proof", func(t *testing.T) {
		_, called, err := ante(recheckCtx(), &bogus)
		require.NoError(t, err)
		require.True(t, called)
	})

	t.Run("ReCheckTx drops a claim whose UTXOs were claimed", func(t *testing.T) {
		ctx, _ := f.ctx.CacheContext()
		claimed := utxo
		claimed.EntitledAmount = 0
		require.NoError(t, f.keeper.Utxoes.Set(ctx, claimed.GetKey(), claimed))
		_, called, err := ante(ctx.WithIsReCheckTx(true), valid)
		require.ErrorContains(t, err, "no valid claimable UTXOs found")
		require.False(t, called)
	})

	t.Run("claims disabled", func(t *testing.T) {
		ctx, _ := f.ctx.CacheContext()
		require.NoError(t, f.keeper.ConstOverrides.Set(ctx, constants.ClaimWithProofDisabled.String(), 1))
		_, called, err := ante(ctx, valid)
		require.ErrorContains(t, err, "ClaimWithProof feature is disabled")
		require.False(t, called)
	})

	t.Run("more than one claim in a free claim tx", func(t *testing.T) {
		_, called, err := ante(f.ctx, valid, valid)
		require.ErrorContains(t, err, "exactly one MsgClaimWithProof")
		require.False(t, called)
	})

	t.Run("a claim the ante handler did not see pays for its verification", func(t *testing.T) {
		ctx, _ := f.ctx.CacheContext()
		ctx = ctx.WithGasMeter(storetypes.NewInfiniteGasMeter())
		_, err := server.ClaimWithProof(ctx, &bogus)
		require.ErrorContains(t, err, "proof verification failed")
		require.GreaterOrEqual(t, ctx.GasMeter().GasConsumed(), keeper.ClaimProofVerifyGas)
	})
}
