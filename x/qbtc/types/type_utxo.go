package types

import (
	"encoding/binary"
	"fmt"
)

// UTXOKeyLen is the byte length of a UTXO collections key (32B txid || 4B BE
// vout). Stored in chain state as the map key.
const UTXOKeyLen = 32 + 4

// UTXOKey returns the canonical store key for a UTXO identified by its 32-byte
// txid (Bitcoin little-endian wire format) and output index. vout is encoded
// big-endian so that ordered iteration groups outputs of the same tx together.
//
// txid must be exactly BitcoinTxIDLength bytes — any other length panics
// rather than silently truncating/zero-padding, since collisions in UTXO key
// identity would corrupt chain state. Caller-side validation
// (ValidateBasic / validateBtcBlockCommit) is expected to reject malformed
// inputs before they reach this path; this panic is defense in depth.
func UTXOKey(txid []byte, vout uint32) string {
	if len(txid) != BitcoinTxIDLength {
		panic(fmt.Sprintf("UTXOKey: txid must be %d bytes, got %d", BitcoinTxIDLength, len(txid)))
	}
	var k [UTXOKeyLen]byte
	copy(k[:32], txid)
	binary.BigEndian.PutUint32(k[32:], vout)
	return string(k[:])
}

// GetKey returns the collections key for this UTXO.
func (m *UTXO) GetKey() string {
	return UTXOKey(m.Txid, m.Vout)
}
