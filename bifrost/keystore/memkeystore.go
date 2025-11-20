package keystore

import (
	"encoding/base64"
	"fmt"
	"sync"

	"github.com/cosmos/cosmos-sdk/crypto/keyring"
)

// memoryKeyStore is a simple in-memory Keystore implementation.
type memoryKeyStore struct {
	keys   map[string]PrivKey
	keysLk sync.Mutex
	ring   keyring.Keyring
}

// NewMemoryKeyStore constructs in-memory Keystore.
func NewMemoryKeyStore() Keystore {
	cdc := setupCodec()
	keybase := setupKeyring(cdc)
	return &memoryKeyStore{
		keys: make(map[string]PrivKey),
		ring: keybase,
	}
}

func (m *memoryKeyStore) Put(n string, k PrivKey) error {
	m.keysLk.Lock()
	defer m.keysLk.Unlock()

	_, ok := m.keys[n]
	if ok {
		return fmt.Errorf("keystore: key '%s' already exists", n)
	}

	m.keys[n] = k
	return nil
}

func (m *memoryKeyStore) Get(n string) (string, error) {
	m.keysLk.Lock()
	defer m.keysLk.Unlock()

	k, ok := m.keys[n]
	if !ok {
		return "", fmt.Errorf("keystore: key '%s' not found", n)
	}

	return base64.StdEncoding.EncodeToString(k.Body), nil
}

func (m *memoryKeyStore) Delete(n string) error {
	m.keysLk.Lock()
	defer m.keysLk.Unlock()

	_, ok := m.keys[n]
	if !ok {
		return fmt.Errorf("keystore: key '%s' not found", n)
	}

	delete(m.keys, n)
	return nil
}

func (m *memoryKeyStore) List() ([]string, error) {
	m.keysLk.Lock()
	defer m.keysLk.Unlock()

	keys := make([]string, 0, len(m.keys))
	for k := range m.keys {
		keys = append(keys, k)
	}

	return keys, nil
}

func (m *memoryKeyStore) Keyring() keyring.Keyring {
	return m.ring
}
