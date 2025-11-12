package types

import "fmt"

func (m *UTXO) GetKey() string {
	return fmt.Sprintf("%s-%d", m.Txid, m.Vout)
}
