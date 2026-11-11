package btcreader_test

import (
	"testing"

	sdkmath "cosmossdk.io/math"

	"github.com/btcq-org/qbtc/x/qbtc/btcreader"
	"github.com/btcq-org/qbtc/x/qbtc/types"
	cryptotypes "github.com/cosmos/cosmos-sdk/crypto/types"
	sdk "github.com/cosmos/cosmos-sdk/types"
	txsigning "github.com/cosmos/cosmos-sdk/types/tx/signing"
	banktypes "github.com/cosmos/cosmos-sdk/x/bank/types"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

// fakeTx implements the minimum subset of sdk.Tx, authsigning.SigVerifiableTx
// and sdk.FeeTx exercised by FreeClaimDecorator.
type fakeTx struct {
	msgs    []sdk.Msg
	signers [][]byte
	payer   []byte
	gas     uint64
}

func (t fakeTx) GetMsgs() []sdk.Msg                                { return t.msgs }
func (t fakeTx) GetMsgsV2() ([]proto.Message, error)               { return nil, nil }
func (t fakeTx) GetSigners() ([][]byte, error)                     { return t.signers, nil }
func (t fakeTx) GetPubKeys() ([]cryptotypes.PubKey, error)         { return nil, nil }
func (t fakeTx) GetSignaturesV2() ([]txsigning.SignatureV2, error) { return nil, nil }
func (t fakeTx) GetGas() uint64                                    { return t.gas }
func (t fakeTx) GetFee() sdk.Coins                                 { return sdk.Coins{} }
func (t fakeTx) FeePayer() []byte                                  { return t.payer }
func (t fakeTx) FeeGranter() []byte                                { return nil }

// A free claim runs with its declared gas clamped to
// [FreeClaimMinGas, FreeClaimMaxGas], and simulation with FreeClaimMaxGas. The
// meter's limit is the gas the tx reports to CometBFT, so it must be finite.
func TestFreeClaimDecorator_GasLimit(t *testing.T) {
	claimer := sdk.AccAddress([]byte("gas-limit-claimer-addr-01"))
	decorator := btcreader.NewFreeClaimDecorator()
	limit := func(declared uint64, simulate bool) uint64 {
		t.Helper()
		tx := fakeTx{
			msgs:    []sdk.Msg{&types.MsgClaimWithProof{Claimer: claimer.String()}},
			signers: [][]byte{claimer},
			gas:     declared,
		}
		var got uint64
		_, err := decorator.AnteHandle(sdk.Context{}, tx, simulate, func(ctx sdk.Context, _ sdk.Tx, _ bool) (sdk.Context, error) {
			got = ctx.GasMeter().Limit()
			return ctx, nil
		})
		require.NoError(t, err)
		return got
	}

	require.Equal(t, types.FreeClaimMinGas, limit(0, false))
	require.Equal(t, uint64(1_000_000), limit(1_000_000, false))
	require.Equal(t, types.FreeClaimMaxGas, limit(1<<62, false))
	require.Equal(t, types.FreeClaimMaxGas, limit(0, true))
}

func TestFreeClaimDecorator_RejectsMultiMsgClaimTx(t *testing.T) {
	claimerA := sdk.AccAddress([]byte("multi-claimer-addr-aaaaaaa"))
	claimerB := sdk.AccAddress([]byte("multi-claimer-addr-bbbbbbb"))

	decorator := btcreader.NewFreeClaimDecorator()

	tx := fakeTx{
		msgs: []sdk.Msg{
			&types.MsgClaimWithProof{Claimer: claimerA.String()},
			&types.MsgClaimWithProof{Claimer: claimerB.String()},
		},
		signers: [][]byte{claimerA, claimerB},
		payer:   claimerA,
	}

	nextCalled := false
	_, err := decorator.AnteHandle(sdk.Context{}, tx, false, func(ctx sdk.Context, _ sdk.Tx, _ bool) (sdk.Context, error) {
		nextCalled = true
		return ctx, nil
	})

	require.Error(t, err, "multi-msg claim tx must be rejected")
	require.False(t, nextCalled, "next decorator must not run when ante rejects")
}

func TestFreeClaimDecorator_SkipsNonClaimTx(t *testing.T) {
	sender := sdk.AccAddress([]byte("bank-sender-addr-1234567890"))

	decorator := btcreader.NewFreeClaimDecorator()

	tx := fakeTx{
		msgs: []sdk.Msg{&banktypes.MsgSend{
			FromAddress: sender.String(),
			ToAddress:   sender.String(),
			Amount:      sdk.NewCoins(sdk.NewInt64Coin("uqbtc", 1)),
		}},
		signers: [][]byte{sender},
		payer:   sender,
	}

	minGasPrices := sdk.NewDecCoins(sdk.NewDecCoinFromDec("qbtc", sdkmath.LegacyNewDecWithPrec(25, 4)))
	var got sdk.DecCoins
	_, err := decorator.AnteHandle(sdk.Context{}.WithMinGasPrices(minGasPrices), tx, false, func(ctx sdk.Context, _ sdk.Tx, _ bool) (sdk.Context, error) {
		got = ctx.MinGasPrices()
		return ctx, nil
	})
	require.NoError(t, err)
	require.Equal(t, minGasPrices, got, "a non-claim tx keeps the minimum gas price")
}
