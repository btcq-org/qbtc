package ebifrost

import (
	"context"

	errorsmod "cosmossdk.io/errors"
	storetypes "cosmossdk.io/store/types"
	"github.com/btcq-org/qbtc/x/qbtc/types"
	sdk "github.com/cosmos/cosmos-sdk/types"
	sdkerrors "github.com/cosmos/cosmos-sdk/types/errors"
	authsigning "github.com/cosmos/cosmos-sdk/x/auth/signing"
)

// AccountKeeper is the subset of x/auth's AccountKeeper the decorator needs to
// pre-create signer accounts for first-time claimers.
type AccountKeeper interface {
	GetAccount(ctx context.Context, addr sdk.AccAddress) sdk.AccountI
	NewAccountWithAddress(ctx context.Context, addr sdk.AccAddress) sdk.AccountI
	SetAccount(ctx context.Context, acc sdk.AccountI)
}

type FreeClaimDecorator struct {
	ak AccountKeeper
}

func NewFreeClaimDecorator(ak AccountKeeper) FreeClaimDecorator {
	return FreeClaimDecorator{ak: ak}
}

// AnteHandle makes MsgClaimWithProof transactions free by setting an infinite
// gas meter and zero minimum gas prices. It also pre-creates the signer
// account when absent, because every claim is by definition a first-time
// on-chain interaction — without this, downstream DeductFee / SetPubKey /
// SigVerification decorators reject the tx with "account does not exist".
// Must be placed after SetUpContextDecorator so the gas meter override takes
// effect for all downstream decorators.
func (fcd FreeClaimDecorator) AnteHandle(ctx sdk.Context, tx sdk.Tx, simulate bool, next sdk.AnteHandler) (sdk.Context, error) {
	if !isClaimOnlyTx(tx) {
		return next(ctx, tx, simulate)
	}

	ctx = ctx.
		WithGasMeter(storetypes.NewInfiniteGasMeter()).
		WithMinGasPrices(sdk.DecCoins{})

	if err := fcd.ensureSignerAccounts(ctx, tx); err != nil {
		return ctx, err
	}

	return next(ctx, tx, simulate)
}

// ensureSignerAccounts creates on-chain accounts for the tx's signers and fee
// payer when they don't exist yet. Safe because FreeClaimDecorator only fires
// on claim-only txs, which are gated by the ZK proof and signature verified
// later in the chain.
func (fcd FreeClaimDecorator) ensureSignerAccounts(ctx sdk.Context, tx sdk.Tx) error {
	sigTx, ok := tx.(authsigning.SigVerifiableTx)
	if !ok {
		return errorsmod.Wrap(sdkerrors.ErrTxDecode, "claim tx must be a SigVerifiableTx")
	}

	signers, err := sigTx.GetSigners()
	if err != nil {
		return err
	}
	for _, signer := range signers {
		fcd.createAccountIfMissing(ctx, signer)
	}

	if feeTx, ok := tx.(sdk.FeeTx); ok {
		if payer := feeTx.FeePayer(); len(payer) > 0 {
			fcd.createAccountIfMissing(ctx, payer)
		}
	}

	return nil
}

func (fcd FreeClaimDecorator) createAccountIfMissing(ctx sdk.Context, addr sdk.AccAddress) {
	if fcd.ak.GetAccount(ctx, addr) != nil {
		return
	}
	fcd.ak.SetAccount(ctx, fcd.ak.NewAccountWithAddress(ctx, addr))
}

// isClaimOnlyTx returns true if the tx contains only MsgClaimWithProof messages.
func isClaimOnlyTx(tx sdk.Tx) bool {
	msgs := tx.GetMsgs()
	if len(msgs) == 0 {
		return false
	}
	for _, msg := range msgs {
		if _, ok := msg.(*types.MsgClaimWithProof); !ok {
			return false
		}
	}
	return true
}
