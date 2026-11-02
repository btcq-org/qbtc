package app

import (
	"fmt"

	abci "github.com/cometbft/cometbft/abci/types"
	cryptoenc "github.com/cometbft/cometbft/crypto/encoding"
	cmtmldsa65 "github.com/cometbft/cometbft/crypto/mldsa65"
	cmttypes "github.com/cometbft/cometbft/types"
)

// validateGenesisValidatorKeyTypes enforces the chain's validator key policy at
// genesis. Staking rejects a MsgCreateValidator or MsgRotateConsPubKey whose
// key type is not in validator.pub_key_types, and CometBFT rejects such a
// validator update at every block, but neither checks the validators a genesis
// file starts with. This checks that pub_key_types is exactly ml_dsa_65 and
// that every genesis validator, from the app's InitGenesis or, failing that,
// from the genesis file, has an ML-DSA-65 key, so a mis-generated genesis
// fails at InitChain instead of starting a chain with legacy validator keys.
func validateGenesisValidatorKeyTypes(req *abci.RequestInitChain, res *abci.ResponseInitChain) error {
	if req.ConsensusParams == nil || req.ConsensusParams.Validator == nil {
		return fmt.Errorf("genesis has no validator consensus params; validator.pub_key_types must be [%q]", cmtmldsa65.KeyType)
	}
	params := cmttypes.ValidatorParams{PubKeyTypes: req.ConsensusParams.Validator.PubKeyTypes}
	if len(params.PubKeyTypes) != 1 || params.PubKeyTypes[0] != cmtmldsa65.KeyType {
		return fmt.Errorf("validator.pub_key_types is %v; the chain accepts only [%q]", params.PubKeyTypes, cmtmldsa65.KeyType)
	}

	validators := res.Validators
	if len(validators) == 0 {
		validators = req.Validators
	}
	for _, v := range validators {
		pk, err := cryptoenc.PubKeyFromProto(v.PubKey)
		if err != nil {
			return fmt.Errorf("genesis validator public key: %w", err)
		}
		if !cmttypes.IsValidPubkeyType(params, pk.Type()) {
			return fmt.Errorf("genesis validator %X has a %s key; validator.pub_key_types allows only %v", pk.Address(), pk.Type(), params.PubKeyTypes)
		}
	}
	return nil
}
