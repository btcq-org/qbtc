package p2p

import (
	"compress/gzip"
	"context"
	"fmt"
	"testing"

	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"
	"github.com/syndtr/goleveldb/leveldb"
	"github.com/syndtr/goleveldb/leveldb/storage"

	qtypes "github.com/btcq-org/qbtc/x/qbtc/types"
)

// noSupermajorityNode accepts every attestation but never reports a
// supermajority, so aggregation stores attestations without forwarding them.
type noSupermajorityNode struct{ mockQBTCNode }

func (noSupermajorityNode) CheckAttestationsSuperMajority(context.Context, *qtypes.MsgBtcBlock) error {
	return fmt.Errorf("no supermajority")
}

func testBlockCommit(t *testing.T, outputs int) []byte {
	t.Helper()
	coinbase := wire.NewMsgTx(2)
	coinbase.AddTxIn(wire.NewTxIn(wire.NewOutPoint(&chainhash.Hash{}, wire.MaxPrevOutIndex), []byte{0x01, 0x02}, nil))
	for i := 0; i < outputs; i++ {
		coinbase.AddTxOut(wire.NewTxOut(int64(i+1), []byte{0x51}))
	}
	block := wire.NewMsgBlock(&wire.BlockHeader{Version: 4})
	require.NoError(t, block.AddTransaction(coinbase))
	commit, err := qtypes.NewBtcBlockCommit(block)
	require.NoError(t, err)
	signBytes, _, err := qtypes.EncodeBtcBlockCommit(commit)
	require.NoError(t, err)
	return signBytes
}

// Attestations sign the uncompressed commit, so two validators' gossip for
// the same block aggregates even when their compressed bytes differ.
func TestAggregateAttestations_KeysByUncompressedCommit(t *testing.T) {
	db, err := leveldb.Open(storage.NewMemStorage(), nil)
	require.NoError(t, err)
	defer db.Close()
	p := &PubSubService{logger: zerolog.Nop(), db: db, qbtcNode: noSupermajorityNode{}}

	signBytes := testBlockCommit(t, 500)
	best, err := qtypes.GzipDeterministic(signBytes, gzip.BestCompression)
	require.NoError(t, err)
	fast, err := qtypes.GzipDeterministic(signBytes, gzip.BestSpeed)
	require.NoError(t, err)
	require.NotEqual(t, best, fast)

	gossip := func(content []byte, validator string) qtypes.BlockGossip {
		return qtypes.BlockGossip{
			Height:       100,
			Hash:         "hash-100",
			BlockContent: content,
			Attestation:  &qtypes.Attestation{Address: validator, Signature: []byte(validator)},
		}
	}
	require.NoError(t, p.aggregateAttestations(gossip(best, "validator-1")))
	require.NoError(t, p.aggregateAttestations(gossip(fast, "validator-2")))

	attestations := func(signBytes []byte) []*qtypes.Attestation {
		stored, err := db.Get([]byte(qtypes.BlockAttestationKey("hash-100", 100, signBytes)), nil)
		require.NoError(t, err)
		var msg qtypes.MsgBtcBlock
		require.NoError(t, msg.Unmarshal(stored))
		return msg.Attestations
	}
	require.Len(t, attestations(signBytes), 2)

	// attestations for different content are kept apart
	otherBytes := testBlockCommit(t, 501)
	other, err := qtypes.GzipDeterministic(otherBytes, gzip.BestCompression)
	require.NoError(t, err)
	require.NoError(t, p.aggregateAttestations(gossip(other, "validator-3")))
	require.Len(t, attestations(otherBytes), 1)
	require.Len(t, attestations(signBytes), 2)
}
