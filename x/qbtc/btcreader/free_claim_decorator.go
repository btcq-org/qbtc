package btcreader

import (
	errorsmod "cosmossdk.io/errors"
	"github.com/btcq-org/qbtc/x/qbtc/types"
	storetypes "github.com/cosmos/cosmos-sdk/store/v2/types"
	sdk "github.com/cosmos/cosmos-sdk/types"
	sdkerrors "github.com/cosmos/cosmos-sdk/types/errors"
)

type FreeClaimDecorator struct{}

func NewFreeClaimDecorator() FreeClaimDecorator {
	return FreeClaimDecorator{}
}

// AnteHandle makes MsgClaimWithProof transactions free: zero minimum gas
// prices, and a gas meter whose limit types.FreeClaimTxGasLimit computes from
// the claim, whatever gas the transaction declares. A free claim larger than
// types.FreeClaimMaxTxBytes is rejected, so the ante handler's charge for its
// bytes cannot use up the gas its message handler needs. The signer must
// already have an account: the claimed coins go to the claimer or receiver,
// whose account the bank send creates, and a first-time claimer's transaction
// is signed by an existing broadcaster such as the proof service. Must be
// placed after SetUpContextDecorator so the gas meter override takes effect for
// all downstream decorators.
func (fcd FreeClaimDecorator) AnteHandle(ctx sdk.Context, tx sdk.Tx, simulate bool, next sdk.AnteHandler) (sdk.Context, error) {
	if !types.IsClaimOnlyTx(tx) {
		return next(ctx, tx, simulate)
	}

	// A free-claim tx carries exactly one MsgClaimWithProof, so it costs one
	// proof verification, the unit MaxClaimsPerBlock and the ante handler's
	// proof check count in. Batch claiming across UTXOs is supported inside a
	// single MsgClaimWithProof via Utxos, so this limit doesn't block any
	// legitimate flow.
	if len(tx.GetMsgs()) != 1 {
		return ctx, errorsmod.Wrap(sdkerrors.ErrInvalidRequest,
			"free-claim tx must contain exactly one MsgClaimWithProof")
	}

	if n := len(ctx.TxBytes()); n > types.FreeClaimMaxTxBytes {
		return ctx, errorsmod.Wrapf(sdkerrors.ErrTxTooLarge,
			"free-claim tx is %d bytes, maximum is %d", n, types.FreeClaimMaxTxBytes)
	}

	ctx = ctx.
		WithGasMeter(storetypes.NewGasMeter(types.FreeClaimTxGasLimit(tx))).
		WithMinGasPrices(sdk.DecCoins{})

	return next(ctx, tx, simulate)
}
