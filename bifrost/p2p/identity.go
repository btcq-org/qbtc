package p2p

import (
	"github.com/btcq-org/qbtc/bifrost/keystore"
	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"
)

const keyName = "bifrost-p2p-key"

// Key provides a networking private key and PeerID of the node.
func Key(kstore keystore.Keystore) (crypto.PrivKey, error) {
	privKey, err := kstore.Get(keyName)
	if err != nil {
		return nil, err
	}
	return crypto.UnmarshalPrivateKey([]byte(privKey))
}

// ID gets the peer id from private key
func ID(key crypto.PrivKey) (peer.ID, error) {
	id, err := peer.IDFromPrivateKey(key)
	if err != nil {
		return "", err
	}
	return id, nil
}
