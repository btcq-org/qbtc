package types

import (
	"cosmossdk.io/collections"
	"cosmossdk.io/collections/indexes"
)

// UTXOIndexes defines the secondary indexes for the UTXO collection.
type UTXOIndexes struct {
	// ByAddress indexes UTXOs by their Bitcoin address (script_pub_key.address).
	ByAddress *indexes.Multi[string, string, UTXO]
}

func (i UTXOIndexes) IndexesList() []collections.Index[string, UTXO] {
	return []collections.Index[string, UTXO]{i.ByAddress}
}

func NewUTXOIndexes(sb *collections.SchemaBuilder) UTXOIndexes {
	return UTXOIndexes{
		ByAddress: indexes.NewMulti(
			sb, UTXOByAddressKeys, "utxoes_by_address",
			collections.StringKey, collections.StringKey,
			func(_ string, utxo UTXO) (string, error) {
				if utxo.ScriptPubKey == nil {
					return "", nil
				}
				return utxo.ScriptPubKey.Address, nil
			},
		),
	}
}
