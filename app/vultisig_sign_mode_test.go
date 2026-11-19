package app

import (
	"context"
	"crypto/sha256"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/anypb"

	"cosmossdk.io/math"

	codectypes "github.com/cosmos/cosmos-sdk/codec/types"
	"github.com/cosmos/cosmos-sdk/crypto/keys/mldsa65"
	sdk "github.com/cosmos/cosmos-sdk/types"
	sdkerrors "github.com/cosmos/cosmos-sdk/types/errors"
	"github.com/cosmos/cosmos-sdk/types/tx/signing"
	authsigning "github.com/cosmos/cosmos-sdk/x/auth/signing"
	authtypes "github.com/cosmos/cosmos-sdk/x/auth/types"
	banktypes "github.com/cosmos/cosmos-sdk/x/bank/types"
	txsigning "github.com/cosmos/cosmos-sdk/x/tx/signing"
	"github.com/cosmos/cosmos-sdk/x/tx/signing/direct"

	"github.com/btcq-org/qbtc/app/signmode"
	qbtcmoduletypes "github.com/btcq-org/qbtc/x/qbtc/types"
)

var signModeVultisig = signing.SignMode(signmode.SignModeVultisig)

// vultisigSigner is an ML-DSA-65 account and how it signs: signFn receives the
// SIGN_MODE_DIRECT SignDoc and returns the signature.
type vultisigSigner struct {
	priv   *mldsa65.PrivKey
	mode   signing.SignMode
	signFn func(t *testing.T, priv *mldsa65.PrivKey, signDoc []byte) []byte
	// accNum and sequence override the on-chain values when set.
	accNum, sequence *uint64
	// pubKey overrides the pubkey put in signer_infos when set.
	pubKey *mldsa65.PubKey
}

func (s vultisigSigner) addr() sdk.AccAddress { return sdk.AccAddress(s.priv.PubKey().Address()) }

// signDigest signs SHA-256 of the SignDoc, as a Vultisig wallet does.
func signDigest(t *testing.T, priv *mldsa65.PrivKey, signDoc []byte) []byte {
	t.Helper()
	digest := sha256.Sum256(signDoc)
	sig, err := priv.Sign(digest[:])
	require.NoError(t, err)
	return sig
}

// signRaw signs the SignDoc itself, as SIGN_MODE_DIRECT expects.
func signRaw(t *testing.T, priv *mldsa65.PrivKey, signDoc []byte) []byte {
	t.Helper()
	sig, err := priv.Sign(signDoc)
	require.NoError(t, err)
	return sig
}

func newMlDsa65Key(t *testing.T) *mldsa65.PrivKey {
	t.Helper()
	priv, err := mldsa65.GenPrivKey()
	require.NoError(t, err)
	return &priv
}

// buildSendTx builds a tx with one MsgSend per signer, signs it as each
// signer says, and round-trips it through the app's tx encoder and decoder.
func buildSendTx(t *testing.T, application *App, ctx sdk.Context, to sdk.AccAddress, denom string, signers ...vultisigSigner) sdk.Tx {
	t.Helper()
	txCfg := application.TxConfig()
	builder := txCfg.NewTxBuilder()

	msgs := make([]sdk.Msg, len(signers))
	for i, s := range signers {
		msgs[i] = banktypes.NewMsgSend(s.addr(), to, sdk.NewCoins(sdk.NewCoin(denom, math.NewInt(1))))
	}
	require.NoError(t, builder.SetMsgs(msgs...))
	builder.SetGasLimit(1_000_000)

	type signerState struct {
		pubKey   *mldsa65.PubKey
		accNum   uint64
		sequence uint64
	}
	states := make([]signerState, len(signers))
	sigs := make([]signing.SignatureV2, len(signers))
	for i, s := range signers {
		acc := application.AuthKeeper.GetAccount(ctx, s.addr())
		require.NotNil(t, acc)
		st := signerState{pubKey: s.priv.PubKey().(*mldsa65.PubKey), accNum: acc.GetAccountNumber(), sequence: acc.GetSequence()}
		if s.accNum != nil {
			st.accNum = *s.accNum
		}
		if s.sequence != nil {
			st.sequence = *s.sequence
		}
		if s.pubKey != nil {
			st.pubKey = s.pubKey
		}
		states[i] = st
		sigs[i] = signing.SignatureV2{PubKey: st.pubKey, Data: &signing.SingleSignatureData{SignMode: s.mode}, Sequence: st.sequence}
	}
	require.NoError(t, builder.SetSignatures(sigs...))

	for i, s := range signers {
		anyPk, err := codectypes.NewAnyWithValue(states[i].pubKey)
		require.NoError(t, err)
		signerData := txsigning.SignerData{
			Address:       s.addr().String(),
			ChainID:       ctx.ChainID(),
			AccountNumber: states[i].accNum,
			Sequence:      states[i].sequence,
			PubKey:        &anypb.Any{TypeUrl: anyPk.TypeUrl, Value: anyPk.Value},
		}
		txData := builder.GetTx().(authsigning.V2AdaptableTx).GetSigningTxData()
		signDoc, err := direct.SignModeHandler{}.GetSignBytes(context.Background(), signerData, txData)
		require.NoError(t, err)
		sigs[i].Data = &signing.SingleSignatureData{SignMode: s.mode, Signature: s.signFn(t, s.priv, signDoc)}
	}
	require.NoError(t, builder.SetSignatures(sigs...))

	bz, err := txCfg.TxEncoder()(builder.GetTx())
	require.NoError(t, err)
	decoded, err := txCfg.TxDecoder()(bz)
	require.NoError(t, err)
	return decoded
}

// withSignMode re-encodes tx with every signer's sign mode replaced, keeping
// the signatures.
func withSignMode(t *testing.T, application *App, tx sdk.Tx, mode signing.SignMode) sdk.Tx {
	t.Helper()
	txCfg := application.TxConfig()
	builder, err := txCfg.WrapTxBuilder(tx)
	require.NoError(t, err)
	sigs, err := tx.(authsigning.Tx).GetSignaturesV2()
	require.NoError(t, err)
	for i := range sigs {
		single := sigs[i].Data.(*signing.SingleSignatureData)
		sigs[i].Data = &signing.SingleSignatureData{SignMode: mode, Signature: single.Signature}
	}
	require.NoError(t, builder.SetSignatures(sigs...))
	bz, err := txCfg.TxEncoder()(builder.GetTx())
	require.NoError(t, err)
	decoded, err := txCfg.TxDecoder()(bz)
	require.NoError(t, err)
	return decoded
}

func TestVultisigSignMode(t *testing.T) {
	application, baseCtx, simAccs := setupTestApp(t)
	baseCtx = baseCtx.WithIsSigverifyTx(true)
	// the simulation genesis randomizes auth params, TxSigLimit included
	require.NoError(t, application.AuthKeeper.Params.Set(baseCtx, authtypes.DefaultParams()))
	to := simAccs[1].Address

	// fund creates the account of a fresh ML-DSA-65 key the way a wallet's
	// account is created: by a claim minting coins to it, which gives it a
	// generated account number.
	var utxoCount int
	fund := func(t *testing.T, ctx sdk.Context) *mldsa65.PrivKey {
		t.Helper()
		priv := newMlDsa65Key(t)
		addr := sdk.AccAddress(priv.PubKey().Address())
		utxoCount++
		txid := fmt.Sprintf("%064x", utxoCount)
		require.NoError(t, application.QbtcKeeper.Utxoes.Set(ctx, txid+"-0", qbtcmoduletypes.UTXO{
			Txid: txid, Amount: 100_000, EntitledAmount: 100_000,
			ScriptPubKey: &qbtcmoduletypes.ScriptPubKeyResult{Type: "pubkeyhash"},
		}))
		require.NoError(t, application.QbtcKeeper.ClaimUTXO(ctx, txid, 0, addr, ""))
		return priv
	}
	denom := func() string {
		ctx, _ := baseCtx.CacheContext()
		balances := application.BankKeeper.GetAllBalances(ctx, sdk.AccAddress(fund(t, ctx).PubKey().Address()))
		require.Len(t, balances, 1)
		return balances[0].Denom
	}()
	ante := application.AnteHandler()
	vultisig := func(priv *mldsa65.PrivKey) vultisigSigner {
		return vultisigSigner{priv: priv, mode: signModeVultisig, signFn: signDigest}
	}
	directSigner := func(priv *mldsa65.PrivKey) vultisigSigner {
		return vultisigSigner{priv: priv, mode: signing.SignMode_SIGN_MODE_DIRECT, signFn: signRaw}
	}

	t.Run("a vultisig signature over SHA-256 of the SignDoc is accepted and the tx runs its ante writes", func(t *testing.T) {
		ctx, _ := baseCtx.CacheContext()
		priv := fund(t, ctx)
		acc := application.AuthKeeper.GetAccount(ctx, sdk.AccAddress(priv.PubKey().Address()))
		require.Nil(t, acc.GetPubKey())
		require.Greater(t, acc.GetAccountNumber(), uint64(1)<<53, "generated account numbers exceed JavaScript's safe integer range")

		for _, checkTx := range []bool{true, false} {
			c, _ := ctx.CacheContext()
			_, err := ante(c.WithIsCheckTx(checkTx), buildSendTx(t, application, c, to, denom, vultisig(priv)), false)
			require.NoError(t, err, "checkTx=%v", checkTx)
		}

		_, err := ante(ctx, buildSendTx(t, application, ctx, to, denom, vultisig(priv)), false)
		require.NoError(t, err)
		acc = application.AuthKeeper.GetAccount(ctx, acc.GetAddress())
		require.Equal(t, uint64(1), acc.GetSequence(), "sequence incremented")
		require.True(t, priv.PubKey().Equals(acc.GetPubKey()), "pubkey stored")

		// second tx: the stored pubkey is used and the next sequence is required
		_, err = ante(ctx, buildSendTx(t, application, ctx, to, denom, vultisig(priv)), false)
		require.NoError(t, err)
	})

	t.Run("a vultisig-mode signature over the SignDoc itself is rejected", func(t *testing.T) {
		ctx, _ := baseCtx.CacheContext()
		priv := fund(t, ctx)
		s := vultisig(priv)
		s.signFn = signRaw
		_, err := ante(ctx, buildSendTx(t, application, ctx, to, denom, s), false)
		require.ErrorIs(t, err, sdkerrors.ErrUnauthorized)
	})

	t.Run("SIGN_MODE_DIRECT is unchanged", func(t *testing.T) {
		ctx, _ := baseCtx.CacheContext()
		priv := fund(t, ctx)
		_, err := ante(ctx, buildSendTx(t, application, ctx, to, denom, directSigner(priv)), false)
		require.NoError(t, err)

		s := directSigner(priv)
		s.signFn = signDigest
		_, err = ante(ctx, buildSendTx(t, application, ctx, to, denom, s), false)
		require.ErrorIs(t, err, sdkerrors.ErrUnauthorized, "a digest signature does not pass as SIGN_MODE_DIRECT")
	})

	t.Run("the signature binds the sign mode", func(t *testing.T) {
		ctx, _ := baseCtx.CacheContext()
		priv := fund(t, ctx)

		relabeled := withSignMode(t, application, buildSendTx(t, application, ctx, to, denom, vultisig(priv)), signing.SignMode_SIGN_MODE_DIRECT)
		_, err := ante(ctx, relabeled, false)
		require.ErrorIs(t, err, sdkerrors.ErrUnauthorized, "vultisig signature relabeled as SIGN_MODE_DIRECT")

		relabeled = withSignMode(t, application, buildSendTx(t, application, ctx, to, denom, directSigner(priv)), signModeVultisig)
		_, err = ante(ctx, relabeled, false)
		require.ErrorIs(t, err, sdkerrors.ErrUnauthorized, "SIGN_MODE_DIRECT signature relabeled as vultisig")
	})

	t.Run("a signature over a wrong account number is rejected", func(t *testing.T) {
		ctx, _ := baseCtx.CacheContext()
		priv := fund(t, ctx)
		acc := application.AuthKeeper.GetAccount(ctx, sdk.AccAddress(priv.PubKey().Address()))
		// A number a float64 cannot hold: a generated one can, by chance.
		require.NoError(t, acc.SetAccountNumber(uint64(1)<<63+1))
		application.AuthKeeper.SetAccount(ctx, acc)
		// the account number after a round trip through a JavaScript Number
		rounded := uint64(float64(acc.GetAccountNumber()))
		require.NotEqual(t, acc.GetAccountNumber(), rounded)
		s := vultisig(priv)
		s.accNum = &rounded
		_, err := ante(ctx, buildSendTx(t, application, ctx, to, denom, s), false)
		require.ErrorIs(t, err, sdkerrors.ErrUnauthorized)
	})

	t.Run("an unknown sign mode is rejected", func(t *testing.T) {
		unknown := func(priv *mldsa65.PrivKey) vultisigSigner {
			return vultisigSigner{priv: priv, mode: signing.SignMode(999), signFn: signDigest}
		}
		// next to a vultisig signer, by this decorator's fall-through to the
		// SDK's verification
		ctx, _ := baseCtx.CacheContext()
		_, err := ante(ctx, buildSendTx(t, application, ctx, to, denom, vultisig(fund(t, ctx)), unknown(fund(t, ctx))), false)
		require.ErrorIs(t, err, sdkerrors.ErrUnauthorized)

		// on its own, by the SDK's decorator
		ctx, _ = baseCtx.CacheContext()
		_, err = ante(ctx, buildSendTx(t, application, ctx, to, denom, unknown(fund(t, ctx))), false)
		require.ErrorIs(t, err, sdkerrors.ErrUnauthorized)
	})

	t.Run("too many signers are rejected before any signature is verified", func(t *testing.T) {
		ctx, _ := baseCtx.CacheContext()
		limit := application.AuthKeeper.GetParams(ctx).TxSigLimit
		signers := make([]vultisigSigner, limit+1)
		for i := range signers {
			signers[i] = vultisig(fund(t, ctx))
			// invalid signatures: verification would fail with ErrUnauthorized
			signers[i].signFn = signRaw
		}
		_, err := ante(ctx, buildSendTx(t, application, ctx, to, denom, signers...), false)
		require.ErrorIs(t, err, sdkerrors.ErrTooManySignatures)
	})

	t.Run("a wrong sequence is rejected", func(t *testing.T) {
		ctx, _ := baseCtx.CacheContext()
		priv := fund(t, ctx)
		seq := uint64(5)
		s := vultisig(priv)
		s.sequence = &seq
		_, err := ante(ctx, buildSendTx(t, application, ctx, to, denom, s), false)
		require.ErrorIs(t, err, sdkerrors.ErrWrongSequence)
	})

	t.Run("a pubkey that does not match the signer address is rejected", func(t *testing.T) {
		ctx, _ := baseCtx.CacheContext()
		priv := fund(t, ctx)
		other := newMlDsa65Key(t)
		s := vultisig(priv)
		s.pubKey = other.PubKey().(*mldsa65.PubKey)
		s.signFn = func(t *testing.T, _ *mldsa65.PrivKey, signDoc []byte) []byte { return signDigest(t, other, signDoc) }
		_, err := ante(ctx, buildSendTx(t, application, ctx, to, denom, s), false)
		require.ErrorIs(t, err, sdkerrors.ErrInvalidPubKey)
	})

	t.Run("every signer of a mixed-mode tx is verified", func(t *testing.T) {
		ctx, _ := baseCtx.CacheContext()
		a, b := fund(t, ctx), fund(t, ctx)
		_, err := ante(ctx, buildSendTx(t, application, ctx, to, denom, vultisig(a), directSigner(b)), false)
		require.NoError(t, err)

		ctx, _ = baseCtx.CacheContext()
		a, b = fund(t, ctx), fund(t, ctx)
		bad := directSigner(b)
		bad.signFn = signDigest
		_, err = ante(ctx, buildSendTx(t, application, ctx, to, denom, vultisig(a), bad), false)
		require.ErrorIs(t, err, sdkerrors.ErrUnauthorized, "an invalid SIGN_MODE_DIRECT co-signer of a vultisig tx")

		ctx, _ = baseCtx.CacheContext()
		a, b = fund(t, ctx), fund(t, ctx)
		badVultisig := vultisig(b)
		badVultisig.signFn = signRaw
		_, err = ante(ctx, buildSendTx(t, application, ctx, to, denom, vultisig(a), badVultisig), false)
		require.ErrorIs(t, err, sdkerrors.ErrUnauthorized, "an invalid second vultisig signer")
	})

	t.Run("simulation and ReCheckTx run as for the SDK's sign modes", func(t *testing.T) {
		ctx, _ := baseCtx.CacheContext()
		priv := fund(t, ctx)
		s := vultisig(priv)
		s.signFn = func(*testing.T, *mldsa65.PrivKey, []byte) []byte { return nil }
		_, err := ante(ctx, buildSendTx(t, application, ctx, to, denom, s), true)
		require.NoError(t, err, "simulate")

		_, err = ante(ctx.WithIsCheckTx(true).WithIsReCheckTx(true), buildSendTx(t, application, ctx, to, denom, vultisig(priv)), false)
		require.NoError(t, err, "recheck")
	})
}
