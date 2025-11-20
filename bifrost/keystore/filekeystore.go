package keystore

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"github.com/cosmos/cosmos-sdk/crypto/keyring"
)

type fileKeyStore struct {
	rootPath string
	keysLk   sync.Mutex
	ring     keyring.Keyring
}

func NewFileKeyStore(rootPath string) (Keystore, error) {
	cdc := setupCodec()
	keybase := setupKeyring(cdc)
	err := ensureDir(rootPath)
	if err != nil {
		return nil, err
	}
	return &fileKeyStore{rootPath: rootPath, ring: keybase}, nil
}

func ensureDir(path string) error {
	err := os.MkdirAll(path, 0755)
	if err != nil && !os.IsExist(err) {
		return fmt.Errorf("keystore: failed to make a dir: %w", err)
	}
	return nil
}

func (f *fileKeyStore) Get(keyName string) (PrivKey, error) {
	rootPath := filepath.Join(f.rootPath, keyName)

	content, err := os.ReadFile(rootPath)
	if err != nil && os.IsNotExist(err) {
		return PrivKey{}, ErrKeyNotFound
	}

	if err != nil {
		return PrivKey{}, err
	}

	k := PrivKey{}
	err = json.Unmarshal(content, &k)
	if err != nil {
		return PrivKey{}, err
	}
	return k, nil
}

func (f *fileKeyStore) Put(keyName string, value PrivKey) error {
	rootPath := filepath.Join(f.rootPath, keyName)

	content, err := json.Marshal(value)
	if err != nil {
		return err
	}

	return os.WriteFile(rootPath, content, 0600)
}

func (f *fileKeyStore) Delete(keyName string) error {
	rootPath := filepath.Join(f.rootPath, keyName)
	return os.Remove(rootPath)
}

func (f *fileKeyStore) Keyring() keyring.Keyring {
	return f.ring
}
