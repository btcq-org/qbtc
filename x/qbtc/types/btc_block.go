package types

import (
	"bytes"
	"compress/gzip"
	"fmt"
	"io"

	"github.com/btcsuite/btcd/wire"
)

const (
	// BtcHeaderSize is the size of a serialized Bitcoin block header.
	BtcHeaderSize = 80

	// MaxBtcBlockCommitSize caps the uncompressed size of a BtcBlockCommit.
	// Bitcoin's 4M weight limit bounds a block without witness data to 1 MB;
	// the rest is headroom for the proto encoding.
	MaxBtcBlockCommitSize = 4 * 1024 * 1024
)

// NewBtcBlockCommit builds the commit for a Bitcoin block: its serialized
// header and each transaction without witness data.
func NewBtcBlockCommit(block *wire.MsgBlock) (*BtcBlockCommit, error) {
	var header bytes.Buffer
	if err := block.Header.Serialize(&header); err != nil {
		return nil, fmt.Errorf("serialize header: %w", err)
	}
	commit := &BtcBlockCommit{
		Header: header.Bytes(),
		Txs:    make([][]byte, len(block.Transactions)),
	}
	for i, tx := range block.Transactions {
		var buf bytes.Buffer
		if err := tx.SerializeNoWitness(&buf); err != nil {
			return nil, fmt.Errorf("serialize tx %d: %w", i, err)
		}
		commit.Txs[i] = buf.Bytes()
	}
	return commit, nil
}

// EncodeBtcBlockCommit returns the bytes validators sign (the commit's proto
// encoding) and the gzip-compressed form carried in MsgBtcBlock.BlockContent.
func EncodeBtcBlockCommit(commit *BtcBlockCommit) (signBytes, content []byte, err error) {
	signBytes, err = commit.Marshal()
	if err != nil {
		return nil, nil, fmt.Errorf("marshal commit: %w", err)
	}
	if len(signBytes) > MaxBtcBlockCommitSize {
		return nil, nil, fmt.Errorf("block commit is %d bytes, maximum is %d", len(signBytes), MaxBtcBlockCommitSize)
	}
	content, err = GzipDeterministic(signBytes, gzip.BestCompression)
	if err != nil {
		return nil, nil, fmt.Errorf("compress commit: %w", err)
	}
	return signBytes, content, nil
}

// DecodeBtcBlockContent decompresses MsgBtcBlock.BlockContent. It returns the
// uncompressed bytes, which are what attestations sign, and the decoded commit.
func DecodeBtcBlockContent(content []byte) ([]byte, *BtcBlockCommit, error) {
	r, err := gzip.NewReader(bytes.NewReader(content))
	if err != nil {
		return nil, nil, fmt.Errorf("gzip: %w", err)
	}
	defer func() {
		_ = r.Close()
	}()
	signBytes, err := io.ReadAll(io.LimitReader(r, MaxBtcBlockCommitSize+1))
	if err != nil {
		return nil, nil, fmt.Errorf("gzip read: %w", err)
	}
	if len(signBytes) > MaxBtcBlockCommitSize {
		return nil, nil, fmt.Errorf("block commit exceeds %d bytes", MaxBtcBlockCommitSize)
	}
	var commit BtcBlockCommit
	if err := commit.Unmarshal(signBytes); err != nil {
		return nil, nil, fmt.Errorf("unmarshal commit: %w", err)
	}
	return signBytes, &commit, nil
}

// ParseBtcBlockCommit decodes the header and transactions of a commit. Each
// transaction must be exactly its canonical serialization without witness
// data, so the signed bytes are canonical and each txid is the double SHA-256
// of the bytes as given.
func ParseBtcBlockCommit(commit *BtcBlockCommit) (*wire.BlockHeader, []*wire.MsgTx, error) {
	if len(commit.Header) != BtcHeaderSize {
		return nil, nil, fmt.Errorf("header is %d bytes, want %d", len(commit.Header), BtcHeaderSize)
	}
	var header wire.BlockHeader
	if err := header.Deserialize(bytes.NewReader(commit.Header)); err != nil {
		return nil, nil, fmt.Errorf("decode header: %w", err)
	}
	txs := make([]*wire.MsgTx, len(commit.Txs))
	for i, raw := range commit.Txs {
		tx := new(wire.MsgTx)
		if err := tx.DeserializeNoWitness(bytes.NewReader(raw)); err != nil {
			return nil, nil, fmt.Errorf("decode tx %d: %w", i, err)
		}
		var canonical bytes.Buffer
		if err := tx.SerializeNoWitness(&canonical); err != nil {
			return nil, nil, fmt.Errorf("serialize tx %d: %w", i, err)
		}
		if !bytes.Equal(canonical.Bytes(), raw) {
			return nil, nil, fmt.Errorf("tx %d is not in canonical serialization without witness data", i)
		}
		txs[i] = tx
	}
	return &header, txs, nil
}
