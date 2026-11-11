package btcreader_test

import (
	"testing"

	sdkmath "cosmossdk.io/math"

	"github.com/btcq-org/qbtc/x/qbtc/btcreader"
	"github.com/btcq-org/qbtc/x/qbtc/types"
	cryptotypes "github.com/cosmos/cosmos-sdk/crypto/types"
	sdk "github.com/cosmos/cosmos-sdk/types"
	sdkerrors "github.com/cosmos/cosmos-sdk/types/errors"
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

// A free claim runs with a gas limit computed from its UTXO count, whatever it
// declares, in simulation too. The meter's limit is the gas the tx reports to
// CometBFT, so it must be finite.
func TestFreeClaimDecorator_GasLimit(t *testing.T) {
	claimer := sdk.AccAddress([]byte("gas-limit-claimer-addr-01"))
	decorator := btcreader.NewFreeClaimDecorator()
	limit := func(numUTXOs int, declared uint64, simulate bool) uint64 {
		t.Helper()
		tx := fakeTx{
			msgs:    []sdk.Msg{&types.MsgClaimWithProof{Claimer: claimer.String(), Utxos: make([]types.UTXORef, numUTXOs)}},
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

	for _, declared := range []uint64{0, 200_000, 1 << 62} {
		for _, simulate := range []bool{false, true} {
			require.Equal(t, types.FreeClaimBaseGas, limit(1, declared, simulate))
			require.Equal(t, types.FreeClaimGasLimit(10), limit(10, declared, simulate))
			require.Equal(t, types.FreeClaimMaxGas, limit(types.MaxBatchClaimUTXOs, declared, simulate))
		}
	}
}

// A free claim padded past FreeClaimMaxTxBytes is rejected: the ante handler
// charges for every byte, out of the gas its message handler needs.
func TestFreeClaimDecorator_RejectsOversizedTx(t *testing.T) {
	claimer := sdk.AccAddress([]byte("oversized-claimer-addr-01"))
	decorator := btcreader.NewFreeClaimDecorator()
	tx := fakeTx{
		msgs:    []sdk.Msg{&types.MsgClaimWithProof{Claimer: claimer.String(), Utxos: make([]types.UTXORef, 1)}},
		signers: [][]byte{claimer},
	}
	next := func(ctx sdk.Context, _ sdk.Tx, _ bool) (sdk.Context, error) { return ctx, nil }

	ctx := sdk.Context{}.WithTxBytes(make([]byte, types.FreeClaimMaxTxBytes))
	_, err := decorator.AnteHandle(ctx, tx, false, next)
	require.NoError(t, err)

	ctx = sdk.Context{}.WithTxBytes(make([]byte, types.FreeClaimMaxTxBytes+1))
	_, err = decorator.AnteHandle(ctx, tx, false, next)
	require.ErrorIs(t, err, sdkerrors.ErrTxTooLarge)
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
