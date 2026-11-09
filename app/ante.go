package app

import (
	"errors"

	"github.com/btcq-org/qbtc/x/qbtc/btcreader"
	"github.com/btcq-org/qbtc/x/qbtc/keeper"
	"github.com/cosmos/cosmos-sdk/client"

	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/cosmos/cosmos-sdk/x/auth/ante"
)

// HandlerOptions are the options required for constructing a default SDK AnteHandler.
type HandlerOptions struct {
	ante.HandlerOptions
	QbtcKeeper *keeper.Keeper
	// AuthKeeper is a superset of ante.AccountKeeper that also exposes
	// NewAccountWithAddress, required by FreeClaimDecorator to pre-create
	// first-time claimers' accounts.
	AuthKeeper btcreader.AccountKeeper
}

// NewAnteHandler returns an AnteHandler that checks and increments sequence
// numbers, checks signatures & account numbers, and deducts fees from the first
// signer.
func NewAnteHandler(options HandlerOptions) (sdk.AnteHandler, error) {
	if options.AccountKeeper == nil {
		return nil, errors.New("account keeper is required for ante builder")
	}
	if options.BankKeeper == nil {
		return nil, errors.New("bank keeper is required for ante builder")
	}
	if options.SignModeHandler == nil {
		return nil, errors.New("sign mode handler is required for ante builder")
	}
	if options.QbtcKeeper == nil {
		return nil, errors.New("qbtc keeper is required for ante builder")
	}
	if options.AuthKeeper == nil {
		return nil, errors.New("auth keeper is required for ante builder")
	}

	anteDecorators := []sdk.AnteDecorator{
		// the injected MsgBtcBlock decorator must be the first decorator to avoid handled messages to be submitted
		btcreader.NewInjectedTxDecorator(),
		// outermost AnteDecorator. SetUpContext must be called first
		ante.NewSetUpContextDecorator(),
		// free gas for MsgClaimWithProof txs — must be after SetUpContext
		btcreader.NewFreeClaimDecorator(options.AuthKeeper),
		ante.NewExtensionOptionsDecorator(options.ExtensionOptionChecker),
		ante.NewValidateBasicDecorator(),
		ante.NewTxTimeoutHeightDecorator(),
		ante.NewValidateMemoDecorator(options.AccountKeeper),
		ante.NewConsumeGasForTxSizeDecorator(options.AccountKeeper),
		ante.NewDeductFeeDecorator(options.AccountKeeper, options.BankKeeper, options.FeegrantKeeper, options.TxFeeChecker),
		ante.NewSetPubKeyDecorator(options.AccountKeeper), // SetPubKeyDecorator must be called before all signature verification decorators
		ante.NewValidateSigCountDecorator(options.AccountKeeper),
		// SigGasConsumer is the account key policy: only ML-DSA-65 keys pass.
		ante.NewSigGasConsumeDecorator(options.AccountKeeper, options.SigGasConsumer),
		ante.NewSigVerificationDecorator(options.AccountKeeper, options.SignModeHandler),
		ante.NewIncrementSequenceDecorator(options.AccountKeeper),
		// verifies a free claim's proof, after its signature: an invalid
		// claim never enters the mempool, and its ante writes roll back
		keeper.NewClaimProofDecorator(options.QbtcKeeper),
	}

	return sdk.ChainAnteDecorators(anteDecorators...), nil
}

func (app *App) setAnteHandler(txConfig client.TxConfig) {
	anteHandler, err := NewAnteHandler(
		HandlerOptions{
			HandlerOptions: ante.HandlerOptions{
				AccountKeeper:   app.AuthKeeper,
				BankKeeper:      app.BankKeeper,
				SignModeHandler: txConfig.SignModeHandler(),
				FeegrantKeeper:  app.FeeGrantKeeper,
				SigGasConsumer:  MlDsa65OnlySigGasConsumer,
			},
			QbtcKeeper: app.QbtcKeeper,
			AuthKeeper: app.AuthKeeper,
		},
	)
	if err != nil {
		panic(err)
	}

	// Set the AnteHandler for the app
	app.SetAnteHandler(anteHandler)
}
