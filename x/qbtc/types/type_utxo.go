package types

import (
	"encoding/binary"
)

// UTXOKeyLen is the byte length of a UTXO collections key (32B txid || 4B BE
// vout). Stored in chain state as the map key.
const UTXOKeyLen = 32 + 4

// UTXOKey returns the canonical store key for a UTXO identified by its 32-byte
// txid (Bitcoin little-endian wire format) and output index. vout is encoded
// big-endian so that ordered iteration groups outputs of the same tx together.
func UTXOKey(txid []byte, vout uint32) string {
	var k [UTXOKeyLen]byte
	copy(k[:32], txid)
	binary.BigEndian.PutUint32(k[32:], vout)
	return string(k[:])
}

// GetKey returns the collections key for this UTXO.
func (m *UTXO) GetKey() string {
	return UTXOKey(m.Txid, m.Vout)
}
