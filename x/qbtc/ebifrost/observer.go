package ebifrost

import (
	"encoding/hex"
	"time"

	"github.com/btcq-org/qbtc/x/qbtc/types"
	"github.com/btcsuite/btcd/btcjson"
	"github.com/btcsuite/btcd/btcutil"
)

// fetchWindow bounds how far ahead of the chain's last-processed height the
// observer caches blocks, so it never races arbitrarily far ahead of consensus.
const fetchWindow = 32

// observe polls Bitcoin and fills the delta cache with blocks above the chain's
// last-processed height (published via SetFloor by ExtendVote), staying
// MinConfirmations behind the tip. It exits when Stop closes stopCh.
func (eb *EnshrinedBifrost) observe() {
	defer eb.wg.Done()

	interval := eb.cfg.PollInterval
	if interval <= 0 {
		interval = 10 * time.Second
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-eb.stopCh:
			return
		case <-ticker.C:
			eb.fetchOnce()
		}
	}
}

func (eb *EnshrinedBifrost) fetchOnce() {
	floor := eb.floor.Load()
	if floor == 0 {
		// No anchor yet: ExtendVote has not reported a last-processed height (or
		// the chain has no btc_initial_height). Nothing sensible to fetch.
		return
	}

	tip, err := eb.btc.GetBlockCount()
	if err != nil {
		eb.logger.Error("observer: failed to get bitcoin tip", "error", err)
		return
	}
	// Stay MinConfirmations behind the tip for reorg safety.
	maxSafe := tip - eb.cfg.MinConfirmations
	maxWant := int64(floor) + fetchWindow

	for h := int64(floor) + 1; h <= maxSafe && h <= maxWant; h++ {
		select {
		case <-eb.stopCh:
			return
		default:
		}
		if eb.hasDelta(uint64(h)) {
			continue
		}
		hash, err := eb.btc.GetBlockHash(h)
		if err != nil {
			if !eb.btc.ShouldBackoff(err) {
				eb.logger.Error("observer: failed to get block hash", "height", h, "error", err)
			}
			return
		}
		block, err := eb.btc.GetBlockVerboseTxs(hash)
		if err != nil {
			if !eb.btc.ShouldBackoff(err) {
				eb.logger.Error("observer: failed to get block", "height", h, "error", err)
			}
			return
		}
		delta, err := buildDelta(block)
		if err != nil {
			eb.logger.Error("observer: failed to build delta", "height", h, "error", err)
			return
		}
		eb.storeDelta(delta)
		eb.logger.Debug("observer: cached btc block delta", "height", h, "hash", block.Hash, "txs", len(block.Tx))
	}
}

// buildDelta converts a verbose Bitcoin block into the minimal BtcBlockDelta.
// It must be deterministic so honest observers produce byte-identical deltas
// (and therefore matching vote-extension digests): all values derive purely
// from block-intrinsic fields, never from node-relative ones like confirmations.
func buildDelta(block *btcjson.GetBlockVerboseTxResult) (*types.BtcBlockDelta, error) {
	blockHash, err := hex.DecodeString(block.Hash)
	if err != nil {
		return nil, err
	}
	var prevHash []byte
	if block.PreviousHash != "" {
		if prevHash, err = hex.DecodeString(block.PreviousHash); err != nil {
			return nil, err
		}
	}

	delta := &types.BtcBlockDelta{
		Height:        uint32(block.Height),
		BlockHash:     blockHash,
		PrevBlockHash: prevHash,
		Txs:           make([]*types.BtcTx, 0, len(block.Tx)),
	}

	for i := range block.Tx {
		tx := block.Tx[i]
		txid, err := hex.DecodeString(tx.Txid)
		if err != nil {
			return nil, err
		}
		bt := &types.BtcTx{Txid: txid}
		for _, in := range tx.Vin {
			if in.IsCoinBase() {
				bt.Coinbase = true
				continue
			}
			prevTxid, err := hex.DecodeString(in.Txid)
			if err != nil {
				return nil, err
			}
			bt.Inputs = append(bt.Inputs, &types.BtcOutpoint{Txid: prevTxid, Vout: in.Vout})
		}
		// Include every output in vout order (index == vout N), so 0-value
		// OP_RETURN claim markers are preserved for claim detection.
		for _, out := range tx.Vout {
			script, err := hex.DecodeString(out.ScriptPubKey.Hex)
			if err != nil {
				return nil, err
			}
			// btcutil.NewAmount rounds the BTC float to the nearest satoshi
			// (and rejects NaN/Inf), avoiding the off-by-one truncation of a
			// raw uint64(value * 1e8) conversion.
			amount, err := btcutil.NewAmount(out.Value)
			if err != nil {
				return nil, err
			}
			bt.Outputs = append(bt.Outputs, &types.BtcTxOut{
				Value:        uint64(amount),
				ScriptPubKey: script,
			})
		}
		delta.Txs = append(delta.Txs, bt)
	}
	return delta, nil
}
