package common

import "github.com/cosmos/cosmos-sdk/types/bech32/legacybech32"

// re-exports
var (
	// GetPubKeyFromBech32 returns a pubkey from a bech32 encoded string
	GetPubKeyFromBech32 = legacybech32.UnmarshalPubKey // nolint SA1019 deprecated
	Bech32ifyPubKey     = legacybech32.MarshalPubKey
	// Bech32PubKeyTypeConsPub consensus public key type
	Bech32PubKeyTypeConsPub = legacybech32.ConsPK
	// Bech32PubKeyTypeAccPub account public key type
	Bech32PubKeyTypeAccPub = legacybech32.AccPK
)
