package testutil

import (
	"encoding/hex"

	"github.com/btcq-org/qbtc/common"
	"github.com/cometbft/cometbft/crypto"
	"github.com/cometbft/cometbft/crypto/mldsa"
	"github.com/cosmos/cosmos-sdk/crypto/codec"
	cryptotypes "github.com/cosmos/cosmos-sdk/crypto/types"
	"github.com/cosmos/cosmos-sdk/types/bech32"
)

// GetRandomPublicKey get a random pubkey for test purpose , the key is in hex string format
func GetRandomPublicKey() string {
	privateKey := mldsa.GenPrivKey()
	pubKey := privateKey.PubKey()
	return hex.EncodeToString(pubKey.Bytes())
}

func GetRandomMLDsaPublicKey() cryptotypes.PubKey {
	privateKey := mldsa.GenPrivKey()
	pubKey := privateKey.PubKey()
	pKey, err := codec.FromCmtPubKeyInterface(pubKey)
	if err != nil {
		panic(err)
	}
	return pKey
}
func GetRandomBech32ConsensusPublicKey() string {
	privateKey := mldsa.GenPrivKey()
	pubKey := privateKey.PubKey()
	pKey, err := codec.FromCmtPubKeyInterface(pubKey)
	if err != nil {
		panic(err)
	}
	bech32PubKey, err := common.Bech32ifyPubKey(common.Bech32PubKeyTypeConsPub, pKey)
	if err != nil {
		panic(err)
	}
	return bech32PubKey
}

func GetRandomBTCQAddress() string {
	name := common.RandHexString(10)
	prefix := common.AccountAddressPrefix
	str, _ := bech32.ConvertAndEncode(prefix, crypto.AddressHash([]byte(name)))
	return str
}
