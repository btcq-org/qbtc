package app

import (
	"testing"

	abci "github.com/cometbft/cometbft/abci/types"
	"github.com/cometbft/cometbft/crypto"
	"github.com/cometbft/cometbft/crypto/ed25519"
	cryptoenc "github.com/cometbft/cometbft/crypto/encoding"
	cmtmldsa65 "github.com/cometbft/cometbft/crypto/mldsa65"
	cmtproto "github.com/cometbft/cometbft/proto/tendermint/types"
	"github.com/stretchr/testify/require"
)

func validatorUpdate(t *testing.T, pk crypto.PubKey) abci.ValidatorUpdate {
	t.Helper()
	proto, err := cryptoenc.PubKeyToProto(pk)
	require.NoError(t, err)
	return abci.ValidatorUpdate{PubKey: proto, Power: 10}
}

func TestValidateGenesisValidatorKeyTypes(t *testing.T) {
	mlKey, err := cmtmldsa65.GenPrivKey()
	require.NoError(t, err)
	mlVal := validatorUpdate(t, mlKey.PubKey())
	edVal := validatorUpdate(t, ed25519.GenPrivKey().PubKey())
	params := func(types ...string) *cmtproto.ConsensusParams {
		return &cmtproto.ConsensusParams{Validator: &cmtproto.ValidatorParams{PubKeyTypes: types}}
	}

	tests := []struct {
		name string
		req  *abci.RequestInitChain
		res  *abci.ResponseInitChain
		err  string
	}{
		{
			name: "ml_dsa_65 validators from InitGenesis",
			req:  &abci.RequestInitChain{ConsensusParams: params(cmtmldsa65.KeyType)},
			res:  &abci.ResponseInitChain{Validators: []abci.ValidatorUpdate{mlVal}},
		},
		{
			name: "ml_dsa_65 validators from the genesis file",
			req:  &abci.RequestInitChain{ConsensusParams: params(cmtmldsa65.KeyType), Validators: []abci.ValidatorUpdate{mlVal}},
			res:  &abci.ResponseInitChain{},
		},
		{
			name: "ed25519 validator",
			req:  &abci.RequestInitChain{ConsensusParams: params(cmtmldsa65.KeyType)},
			res:  &abci.ResponseInitChain{Validators: []abci.ValidatorUpdate{mlVal, edVal}},
			err:  "has a ed25519 key",
		},
		{
			name: "ed25519 allowed by pub_key_types",
			req:  &abci.RequestInitChain{ConsensusParams: params(cmtmldsa65.KeyType, ed25519.KeyType)},
			res:  &abci.ResponseInitChain{Validators: []abci.ValidatorUpdate{mlVal}},
			err:  "accepts only",
		},
		{
			name: "no validator params",
			req:  &abci.RequestInitChain{},
			res:  &abci.ResponseInitChain{Validators: []abci.ValidatorUpdate{mlVal}},
			err:  "no validator consensus params",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := validateGenesisValidatorKeyTypes(tc.req, tc.res)
			if tc.err == "" {
				require.NoError(t, err)
				return
			}
			require.ErrorContains(t, err, tc.err)
		})
	}
}
