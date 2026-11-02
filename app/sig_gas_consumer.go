package app

import (
	errorsmod "cosmossdk.io/errors"

	"github.com/cosmos/cosmos-sdk/crypto/keys/mldsa65"
	storetypes "github.com/cosmos/cosmos-sdk/store/v2/types"
	sdkerrors "github.com/cosmos/cosmos-sdk/types/errors"
	"github.com/cosmos/cosmos-sdk/types/tx/signing"
	authtypes "github.com/cosmos/cosmos-sdk/x/auth/types"
)

// MlDsa65OnlySigGasConsumer is the chain's account key policy. It charges the
// ML-DSA-65 signature verification cost for a bare mldsa65.PubKey and rejects
// every other key type with ErrInvalidPubKey: secp256k1, ed25519, secp256r1,
// secp256k1eth and multisig, including a multisig of ML-DSA-65 members.
//
// SigGasConsumeDecorator runs it for every signer of every transaction, with
// the pubkey SetPubKeyDecorator just took from signer_infos (or the one already
// on the account), so it rejects a legacy key whether it is new or stored.
// Validators' consensus keys are restricted separately, by the ml_dsa_65-only
// validator.pub_key_types consensus parameter.
//
// In simulate mode a transaction without a pubkey in signer_infos, from an
// account without one on chain, gets the SDK's sentinel secp256k1 key and is
// rejected here: gas simulation must carry the signer's pubkey. The SDK tx
// factory and the proof-service broadcaster both do.
func MlDsa65OnlySigGasConsumer(meter storetypes.GasMeter, sig signing.SignatureV2, params authtypes.Params) error {
	switch pk := sig.PubKey.(type) {
	case *mldsa65.PubKey:
		meter.ConsumeGas(params.SigVerifyCostMlDsa65, "ante verify: ml_dsa_65")
		return nil
	default:
		return errorsmod.Wrapf(sdkerrors.ErrInvalidPubKey, "only ml_dsa_65 account keys are accepted, got %T", pk)
	}
}
