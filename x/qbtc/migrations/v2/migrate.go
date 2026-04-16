package v2

import (
	"context"

	"cosmossdk.io/collections"

	"github.com/btcq-org/qbtc/x/qbtc/types"
)

// MigrateStore rebuilds the Utxoes ByAddress secondary index for entries that
// were written before the index existed (ConsensusVersion 1).
//
// Why: the index is populated by collections.IndexedMap on Set, so pre-existing
// UTXOs need to be re-Set once so the new `idx_utxo_by_addr` prefix is filled.
// How: collect primary keys in a first pass, then re-fetch and re-Set each
// entry — re-using the live iterator across writes is unsafe.
func MigrateStore(
	ctx context.Context,
	utxoes *collections.IndexedMap[string, types.UTXO, types.UTXOIndexes],
) error {
	var keys []string
	if err := utxoes.Walk(ctx, nil, func(key string, _ types.UTXO) (stop bool, err error) {
		keys = append(keys, key)
		return false, nil
	}); err != nil {
		return err
	}

	for _, key := range keys {
		utxo, err := utxoes.Get(ctx, key)
		if err != nil {
			return err
		}
		if err := utxoes.Set(ctx, key, utxo); err != nil {
			return err
		}
	}
	return nil
}
