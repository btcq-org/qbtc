package types

import (
	"bytes"
	"compress/gzip"
	"encoding/hex"
	"testing"

	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
	"github.com/stretchr/testify/require"
)

// testBlock has a coinbase and a transaction with witness data.
func testBlock(t *testing.T) *wire.MsgBlock {
	t.Helper()
	coinbase := wire.NewMsgTx(2)
	coinbase.AddTxIn(wire.NewTxIn(wire.NewOutPoint(&chainhash.Hash{}, wire.MaxPrevOutIndex), []byte{0x03, 0x01, 0x02, 0x03}, nil))
	coinbase.AddTxOut(wire.NewTxOut(312_500_000, []byte{0x51}))
	spend := wire.NewMsgTx(2)
	spend.AddTxIn(wire.NewTxIn(wire.NewOutPoint(&chainhash.Hash{7}, 1), nil, wire.TxWitness{[]byte{0xaa, 0xbb}, []byte{0xcc}}))
	spend.AddTxOut(wire.NewTxOut(90_000, []byte{0x00, 0x14, 0x01, 0x02}))
	block := wire.NewMsgBlock(&wire.BlockHeader{Version: 4, PrevBlock: chainhash.Hash{9}, Bits: 0x207fffff})
	require.NoError(t, block.AddTransaction(coinbase))
	require.NoError(t, block.AddTransaction(spend))
	return block
}

func TestBtcBlockCommit_RoundTrip(t *testing.T) {
	block := testBlock(t)
	commit, err := NewBtcBlockCommit(block)
	require.NoError(t, err)
	signBytes, content, err := EncodeBtcBlockCommit(commit)
	require.NoError(t, err)

	decodedBytes, decoded, err := DecodeBtcBlockContent(content)
	require.NoError(t, err)
	require.Equal(t, signBytes, decodedBytes)
	header, txs, err := ParseBtcBlockCommit(decoded)
	require.NoError(t, err)
	require.Equal(t, block.BlockHash(), header.BlockHash())
	require.Len(t, txs, 2)
	for i, tx := range txs {
		require.Equal(t, block.Transactions[i].TxHash(), tx.TxHash())
		require.Empty(t, tx.TxIn[0].Witness, "witness data is not carried")
	}
}

func TestDecodeBtcBlockContent_Limits(t *testing.T) {
	oversized, err := GzipDeterministic(make([]byte, MaxBtcBlockCommitSize+1), gzip.BestCompression)
	require.NoError(t, err)
	_, _, err = DecodeBtcBlockContent(oversized)
	require.ErrorContains(t, err, "exceeds")

	_, _, err = DecodeBtcBlockContent([]byte("not gzip"))
	require.ErrorContains(t, err, "gzip")
}

func TestParseBtcBlockCommit_Rejects(t *testing.T) {
	commit, err := NewBtcBlockCommit(testBlock(t))
	require.NoError(t, err)

	short := *commit
	short.Header = short.Header[:79]
	_, _, err = ParseBtcBlockCommit(&short)
	require.ErrorContains(t, err, "header is 79 bytes")

	trailing := *commit
	trailing.Txs = [][]byte{append(bytes.Clone(commit.Txs[0]), 0x00), commit.Txs[1]}
	_, _, err = ParseBtcBlockCommit(&trailing)
	require.ErrorContains(t, err, "canonical")

	// the segwit serialization (with witness) is not accepted either
	var withWitness bytes.Buffer
	require.NoError(t, testBlock(t).Transactions[1].Serialize(&withWitness))
	segwit := *commit
	segwit.Txs = [][]byte{commit.Txs[0], withWitness.Bytes()}
	_, _, err = ParseBtcBlockCommit(&segwit)
	require.Error(t, err)
}

// Real mainnet headers: 919295 and the first block of its difficulty period.
const (
	anchorHeader919295 = "0400f02f5ce8660343f270c5c0cb90d2c069e5a69b54b0f76e8a000000000000000000007dc9b6f78b18d51ce2bc08fbb99ef79b18fbf19d5450b0bc14fa1c924c40d6756881f068b4dd0117d2dc74d5"
	periodStart917280  = 1759348633
)

func TestGenesisState_ValidateBtcAnchor(t *testing.T) {
	anchor, err := hex.DecodeString(anchorHeader919295)
	require.NoError(t, err)
	badPoW := bytes.Clone(anchor)
	badPoW[79] ^= 0xff // nonce

	cases := []struct {
		name    string
		gs      GenesisState
		wantErr string
	}{
		{"no anchor and no initial height", GenesisState{}, ""},
		{"valid mainnet anchor", GenesisState{BtcInitialHeight: 919296, BtcAnchorHeader: anchor, BtcAnchorPeriodStartTime: periodStart917280}, ""},
		{"initial height without anchor", GenesisState{BtcInitialHeight: 919296}, "btc_anchor_header is required"},
		{"anchor without initial height", GenesisState{BtcAnchorHeader: anchor, BtcAnchorPeriodStartTime: periodStart917280}, "btc_initial_height is required"},
		{"short anchor", GenesisState{BtcInitialHeight: 919296, BtcAnchorHeader: anchor[:79], BtcAnchorPeriodStartTime: periodStart917280}, "79 bytes"},
		{"anchor without proof of work", GenesisState{BtcInitialHeight: 919296, BtcAnchorHeader: badPoW, BtcAnchorPeriodStartTime: periodStart917280}, "proof-of-work"},
		{"no period start", GenesisState{BtcInitialHeight: 919296, BtcAnchorHeader: anchor}, "btc_anchor_period_start_time"},
		{"period start after the anchor", GenesisState{BtcInitialHeight: 919296, BtcAnchorHeader: anchor, BtcAnchorPeriodStartTime: 2_000_000_000}, "btc_anchor_period_start_time"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.gs.Validate()
			if tc.wantErr == "" {
				require.NoError(t, err)
			} else {
				require.ErrorContains(t, err, tc.wantErr)
			}
		})
	}
}
