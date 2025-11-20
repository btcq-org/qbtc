package keystore

import (
	"crypto/rand"

	"github.com/cosmos/cosmos-sdk/codec"
	codectypes "github.com/cosmos/cosmos-sdk/codec/types"
	cryptocodec "github.com/cosmos/cosmos-sdk/crypto/codec"
	"github.com/cosmos/cosmos-sdk/crypto/keyring"
	"github.com/libp2p/go-libp2p/core/crypto"
)

type PrivKey struct {
	Body []byte
}

type Keystore interface {
	Get(key string) (string, error)
	Put(key string, value PrivKey) error
	Keyring() keyring.Keyring
}

func setupKeyring(cdc codec.Codec) keyring.Keyring {
	k := keyring.NewInMemory(cdc)
	return k
}

func setupCodec() codec.Codec {
	registry := codectypes.NewInterfaceRegistry()
	cryptocodec.RegisterInterfaces(registry)
	cdc := codec.NewProtoCodec(registry)
	return cdc
}

// GenerateKey creates a new random ed25519 private key for the p2p network
func GenerateKey(kstore Keystore) (*PrivKey, error) {
	// No existing private key in the keystore so generate a new one
	priv, _, err := crypto.GenerateEd25519Key(rand.Reader)
	if err != nil {
		return nil, err
	}

	bytes, err := crypto.MarshalPrivateKey(priv)
	if err != nil {
		return nil, err
	}

	privKey := &PrivKey{Body: bytes}

	return privKey, nil
}
