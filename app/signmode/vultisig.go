// Package signmode holds the qbtc-specific transaction sign modes.
//
// SignModeVultisig lets a signer whose ML-DSA implementation only signs a
// 32-byte message, such as the Vultisig wallet's threshold signer, sign a
// transaction: its sign bytes are the SHA-256 digest of the SIGN_MODE_DIRECT
// SignDoc. The SignDoc commits to the auth info, and with it to each signer's
// sign mode, so a signature made in one mode never verifies in the other.
package signmode

import (
	"bytes"
	"context"
	"crypto/sha256"

	"google.golang.org/protobuf/types/known/anypb"

	signingv1beta1 "cosmossdk.io/api/cosmos/tx/signing/v1beta1"
	errorsmod "cosmossdk.io/errors"

	codectypes "github.com/cosmos/cosmos-sdk/codec/types"
	sdk "github.com/cosmos/cosmos-sdk/types"
	sdkerrors "github.com/cosmos/cosmos-sdk/types/errors"
	"github.com/cosmos/cosmos-sdk/types/tx/signing"
	"github.com/cosmos/cosmos-sdk/x/auth/ante"
	authsigning "github.com/cosmos/cosmos-sdk/x/auth/signing"
	txsigning "github.com/cosmos/cosmos-sdk/x/tx/signing"
	"github.com/cosmos/cosmos-sdk/x/tx/signing/direct"
)

// SignModeVultisig is the sign mode value a signer puts in
// signer_infos[i].mode_info.single.mode. It is outside every value the SDK
// has assigned (0-3, 127, 191).
const SignModeVultisig signingv1beta1.SignMode = 1000

// signModeVultisigInternal is SignModeVultisig as the SDK's gogoproto enum,
// the type a decoded transaction's signature data carries.
const signModeVultisigInternal = signing.SignMode(SignModeVultisig)

var _ txsigning.SignModeHandler = VultisigSignModeHandler{}

// VultisigSignModeHandler computes the sign bytes of SignModeVultisig:
// SHA-256 of the SIGN_MODE_DIRECT SignDoc.
type VultisigSignModeHandler struct{}

// Mode implements txsigning.SignModeHandler.
func (VultisigSignModeHandler) Mode() signingv1beta1.SignMode {
	return SignModeVultisig
}

// GetSignBytes implements txsigning.SignModeHandler.
func (VultisigSignModeHandler) GetSignBytes(ctx context.Context, signerData txsigning.SignerData, txData txsigning.TxData) ([]byte, error) {
	signDoc, err := direct.SignModeHandler{}.GetSignBytes(ctx, signerData, txData)
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256(signDoc)
	return digest[:], nil
}

// VultisigSigVerificationDecorator verifies the signatures of a transaction
// that has at least one SignModeVultisig signer. The SDK's
// SigVerificationDecorator only verifies the SDK's own sign modes, so for such
// a transaction this decorator checks each signer's pubkey against its address
// and verifies every signature, in any mode, and then runs the rest of the
// chain with signature verification turned off. That flag only gates those two
// checks: sequence and unordered-nonce checks, pubkey setting, signature gas
// and the sequence increment still run.
//
// A transaction without a SignModeVultisig signer passes through unchanged. It
// must be placed before ante.SetPubKeyDecorator.
type VultisigSigVerificationDecorator struct {
	ak              ante.AccountKeeper
	signModeHandler *txsigning.HandlerMap
}

// NewVultisigSigVerificationDecorator returns a VultisigSigVerificationDecorator.
// signModeHandler verifies the signatures of the transaction's other signers.
func NewVultisigSigVerificationDecorator(ak ante.AccountKeeper, signModeHandler *txsigning.HandlerMap) VultisigSigVerificationDecorator {
	return VultisigSigVerificationDecorator{ak: ak, signModeHandler: signModeHandler}
}

// AnteHandle implements sdk.AnteDecorator.
func (d VultisigSigVerificationDecorator) AnteHandle(ctx sdk.Context, tx sdk.Tx, simulate bool, next sdk.AnteHandler) (sdk.Context, error) {
	// The SDK verifies no signature in these cases, so neither does this
	// decorator, and the SDK decorators do not reject the sign mode.
	if simulate || ctx.IsReCheckTx() || !ctx.IsSigverifyTx() {
		return next(ctx, tx, simulate)
	}
	sigTx, ok := tx.(authsigning.Tx)
	if !ok {
		return next(ctx, tx, simulate)
	}
	sigs, err := sigTx.GetSignaturesV2()
	if err != nil {
		return ctx, err
	}
	if !hasVultisigSigner(sigs) {
		return next(ctx, tx, simulate)
	}

	adaptableTx, ok := tx.(authsigning.V2AdaptableTx)
	if !ok {
		return ctx, errorsmod.Wrapf(sdkerrors.ErrTxDecode, "expected tx to implement V2AdaptableTx, got %T", tx)
	}
	signers, err := sigTx.GetSigners()
	if err != nil {
		return ctx, err
	}
	if len(sigs) != len(signers) {
		return ctx, errorsmod.Wrapf(sdkerrors.ErrUnauthorized, "invalid number of signer;  expected: %d, got %d", len(signers), len(sigs))
	}
	txData := adaptableTx.GetSigningTxData()
	chainID := ctx.ChainID()
	genesis := ctx.BlockHeight() == 0

	for i, sig := range sigs {
		acc, err := ante.GetSignerAcc(ctx, d.ak, signers[i])
		if err != nil {
			return ctx, err
		}
		// The account's stored pubkey, or for its first transaction the one in
		// signer_infos, which SetPubKeyDecorator stores next.
		pubKey := acc.GetPubKey()
		if pubKey == nil {
			pubKey = sig.PubKey
		}
		if pubKey == nil {
			return ctx, errorsmod.Wrap(sdkerrors.ErrInvalidPubKey, "pubkey on account is not set")
		}
		if !bytes.Equal(pubKey.Address(), signers[i]) {
			return ctx, errorsmod.Wrapf(sdkerrors.ErrInvalidPubKey,
				"pubKey does not match signer address %s with signer index: %d", acc.GetAddress(), i)
		}

		var accNum uint64
		if !genesis {
			accNum = acc.GetAccountNumber()
		}
		anyPk, err := codectypes.NewAnyWithValue(pubKey)
		if err != nil {
			return ctx, err
		}
		signerData := txsigning.SignerData{
			Address:       acc.GetAddress().String(),
			ChainID:       chainID,
			AccountNumber: accNum,
			Sequence:      sig.Sequence,
			PubKey:        &anypb.Any{TypeUrl: anyPk.TypeUrl, Value: anyPk.Value},
		}

		if single, ok := sig.Data.(*signing.SingleSignatureData); ok && single.SignMode == signModeVultisigInternal {
			signBytes, err := VultisigSignModeHandler{}.GetSignBytes(ctx, signerData, txData)
			if err != nil {
				return ctx, err
			}
			if !pubKey.VerifySignature(signBytes, single.Signature) {
				return ctx, errorsmod.Wrapf(sdkerrors.ErrUnauthorized,
					"signature verification failed; please verify account number (%d) and chain-id (%s): (unable to verify vultisig sign mode signature)",
					accNum, chainID)
			}
			continue
		}
		if err := authsigning.VerifySignature(ctx, pubKey, signerData, sig.Data, d.signModeHandler, txData); err != nil {
			return ctx, errorsmod.Wrapf(sdkerrors.ErrUnauthorized,
				"signature verification failed; please verify account number (%d) and chain-id (%s): (%s)", accNum, chainID, err)
		}
	}

	return next(ctx.WithIsSigverifyTx(false), tx, simulate)
}

func hasVultisigSigner(sigs []signing.SignatureV2) bool {
	for _, sig := range sigs {
		if single, ok := sig.Data.(*signing.SingleSignatureData); ok && single.SignMode == signModeVultisigInternal {
			return true
		}
	}
	return false
}
