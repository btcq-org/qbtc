package keeper

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"math/big"
	"time"

	"cosmossdk.io/collections"
	"github.com/btcsuite/btcd/blockchain"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
)

// btcTip is the stored Bitcoin block that the next reported block must extend.
type btcTip struct {
	header      wire.BlockHeader
	periodStart int64
}

// getBtcTip returns the stored tip. Without one (no genesis anchor), no Bitcoin
// block can be accepted.
func (k Keeper) getBtcTip(ctx context.Context) (*btcTip, error) {
	raw, err := k.BtcTipHeader.Get(ctx)
	if errors.Is(err, collections.ErrNotFound) {
		return nil, fmt.Errorf("no Bitcoin anchor header in genesis")
	}
	if err != nil {
		return nil, err
	}
	var tip btcTip
	if err := tip.header.Deserialize(bytes.NewReader(raw)); err != nil {
		return nil, fmt.Errorf("decode stored tip header: %w", err)
	}
	periodStart, err := k.BtcPeriodStartTime.Get(ctx)
	if err != nil {
		return nil, fmt.Errorf("read period start time: %w", err)
	}
	tip.periodStart = int64(periodStart)
	return &tip, nil
}

// setBtcTip stores header as the new tip. At a difficulty period boundary its
// timestamp becomes the period start for the next retarget.
func (k Keeper) setBtcTip(ctx context.Context, params *chaincfg.Params, height uint64, header *wire.BlockHeader) error {
	var buf bytes.Buffer
	if err := header.Serialize(&buf); err != nil {
		return err
	}
	if err := k.BtcTipHeader.Set(ctx, buf.Bytes()); err != nil {
		return err
	}
	if height%blocksPerRetarget(params) == 0 {
		return k.BtcPeriodStartTime.Set(ctx, uint64(header.Timestamp.Unix()))
	}
	return nil
}

func blocksPerRetarget(params *chaincfg.Params) uint64 {
	return uint64(params.TargetTimespan / params.TargetTimePerBlock)
}

// requiredBits returns the difficulty bits the block at height must carry,
// following Bitcoin's retarget rule (as btcd's calcNextRequiredDifficulty):
// unchanged inside a period, and at a boundary the previous target scaled by
// the time the previous period took, clamped to a factor of 4.
func requiredBits(params *chaincfg.Params, height uint64, tip *btcTip) uint32 {
	if params.PoWNoRetargeting {
		return params.PowLimitBits
	}
	if height%blocksPerRetarget(params) != 0 {
		return tip.header.Bits
	}
	targetTimespan := int64(params.TargetTimespan / time.Second)
	adjustment := params.RetargetAdjustmentFactor
	timespan := tip.header.Timestamp.Unix() - tip.periodStart
	timespan = max(timespan, targetTimespan/adjustment)
	timespan = min(timespan, targetTimespan*adjustment)

	target := new(big.Int).Mul(blockchain.CompactToBig(tip.header.Bits), big.NewInt(timespan))
	target.Div(target, big.NewInt(targetTimespan))
	if target.Cmp(params.PowLimit) > 0 {
		target.Set(params.PowLimit)
	}
	return blockchain.BigToCompact(target)
}

// verifyBtcBlock checks a reported block against the stored tip: the header
// hash is hash, the header links to the tip, carries the required difficulty
// and meets it, the first transaction (and only it) is a coinbase that encodes
// the height where BIP34 applies, no txid repeats, and the merkle root of the
// txids matches the header. It returns the txids in block order.
//
// Not checked: median-time-past and future-timestamp rules. Breaking them
// still needs headers that meet the current difficulty.
func verifyBtcBlock(params *chaincfg.Params, tip *btcTip, height uint64, hash string, header *wire.BlockHeader, txs []*wire.MsgTx) ([]chainhash.Hash, error) {
	blockHash := header.BlockHash()
	if blockHash.String() != hash {
		return nil, fmt.Errorf("header hash %s does not match block hash %s", blockHash, hash)
	}
	if tipHash := tip.header.BlockHash(); header.PrevBlock != tipHash {
		return nil, fmt.Errorf("block %s builds on %s, not on the last processed block %s", blockHash, header.PrevBlock, tipHash)
	}
	if want := requiredBits(params, height, tip); header.Bits != want {
		return nil, fmt.Errorf("block %s has difficulty bits %08x, want %08x", blockHash, header.Bits, want)
	}
	target := blockchain.CompactToBig(header.Bits)
	if target.Sign() <= 0 || target.Cmp(params.PowLimit) > 0 {
		return nil, fmt.Errorf("block %s has an invalid target %08x", blockHash, header.Bits)
	}
	if blockchain.HashToBig(&blockHash).Cmp(target) > 0 {
		return nil, fmt.Errorf("block %s does not meet its proof-of-work target", blockHash)
	}

	if len(txs) == 0 || !blockchain.IsCoinBaseTx(txs[0]) {
		return nil, fmt.Errorf("block %s does not start with a coinbase transaction", blockHash)
	}
	utxs := make([]*btcutil.Tx, len(txs))
	txids := make([]chainhash.Hash, len(txs))
	seen := make(map[chainhash.Hash]struct{}, len(txs))
	for i, tx := range txs {
		if i > 0 && blockchain.IsCoinBaseTx(tx) {
			return nil, fmt.Errorf("block %s has a second coinbase transaction at index %d", blockHash, i)
		}
		utxs[i] = btcutil.NewTx(tx)
		txids[i] = tx.TxHash()
		// Repeated txids let a different transaction list produce the same
		// merkle root (CVE-2012-2459).
		if _, dup := seen[txids[i]]; dup {
			return nil, fmt.Errorf("block %s repeats transaction %s", blockHash, txids[i])
		}
		seen[txids[i]] = struct{}{}
	}
	if height >= uint64(params.BIP0034Height) {
		coinbaseHeight, err := blockchain.ExtractCoinbaseHeight(utxs[0])
		if err != nil {
			return nil, fmt.Errorf("block %s coinbase height: %w", blockHash, err)
		}
		if coinbaseHeight < 0 || uint64(coinbaseHeight) != height {
			return nil, fmt.Errorf("block %s coinbase encodes height %d, not %d", blockHash, coinbaseHeight, height)
		}
	}
	if root := blockchain.CalcMerkleRoot(utxs, false); root != header.MerkleRoot {
		return nil, fmt.Errorf("block %s merkle root %s does not match the header %s", blockHash, root, header.MerkleRoot)
	}
	return txids, nil
}
