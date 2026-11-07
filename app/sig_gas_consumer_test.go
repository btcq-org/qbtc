package app

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/cosmos/cosmos-sdk/crypto/keys/ed25519"
	"github.com/cosmos/cosmos-sdk/crypto/keys/mldsa65"
	kmultisig "github.com/cosmos/cosmos-sdk/crypto/keys/multisig"
	"github.com/cosmos/cosmos-sdk/crypto/keys/secp256k1"
	"github.com/cosmos/cosmos-sdk/crypto/keys/secp256r1"
	cryptotypes "github.com/cosmos/cosmos-sdk/crypto/types"
	storetypes "github.com/cosmos/cosmos-sdk/store/v2/types"
	sdkerrors "github.com/cosmos/cosmos-sdk/types/errors"
	"github.com/cosmos/cosmos-sdk/types/tx/signing"
	authtypes "github.com/cosmos/cosmos-sdk/x/auth/types"
)

func mustMlDsa65PubKey(t *testing.T) cryptotypes.PubKey {
	t.Helper()
	priv, err := mldsa65.GenPrivKey()
	require.NoError(t, err)
	return priv.PubKey()
}

func TestMlDsa65OnlySigGasConsumer(t *testing.T) {
	params := authtypes.DefaultParams()
	secp256r1Key, err := secp256r1.GenPrivKey()
	require.NoError(t, err)
	mlKey1, mlKey2 := mustMlDsa65PubKey(t), mustMlDsa65PubKey(t)

	tests := []struct {
		name   string
		pubKey cryptotypes.PubKey
		data   signing.SignatureData
		ok     bool
	}{
		{name: "ml_dsa_65", pubKey: mlKey1, data: &signing.SingleSignatureData{}, ok: true},
		{name: "secp256k1", pubKey: secp256k1.GenPrivKey().PubKey(), data: &signing.SingleSignatureData{}},
		{name: "ed25519", pubKey: ed25519.GenPrivKey().PubKey(), data: &signing.SingleSignatureData{}},
		{name: "secp256r1", pubKey: secp256r1Key.PubKey(), data: &signing.SingleSignatureData{}},
		{
			name:   "multisig of ml_dsa_65 members",
			pubKey: kmultisig.NewLegacyAminoPubKey(2, []cryptotypes.PubKey{mlKey1, mlKey2}),
			data:   &signing.MultiSignatureData{},
		},
		{name: "nil pubkey", pubKey: nil, data: &signing.SingleSignatureData{}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			meter := storetypes.NewInfiniteGasMeter()
			err := MlDsa65OnlySigGasConsumer(meter, signing.SignatureV2{PubKey: tc.pubKey, Data: tc.data}, params)
			if !tc.ok {
				require.ErrorIs(t, err, sdkerrors.ErrInvalidPubKey)
				require.Zero(t, meter.GasConsumed())
				return
			}
			require.NoError(t, err)
			require.Equal(t, params.SigVerifyCostMlDsa65, meter.GasConsumed())
		})
	}
}
