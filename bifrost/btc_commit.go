package bifrost

import (
	"encoding/hex"
	"fmt"
	"math"
	"strings"

	"github.com/btcq-org/qbtc/x/qbtc/types"
	"github.com/btcq-org/qbtc/x/qbtc/zk"
	"github.com/btcsuite/btcd/btcjson"
	"github.com/rs/zerolog/log"
)

// buildBtcBlockCommit converts a Bitcoin RPC verbose-tx result into the slim
// BtcBlockCommit qbtc consumes. Outputs whose addresses don't decode to a
// hash160 (P2PKH/P2WPKH) are still included for merkle-root coverage but
// carry an empty Address — the chain only stores UTXOs for supported types.
func buildBtcBlockCommit(b *btcjson.GetBlockVerboseTxResult) (*types.BtcBlockCommit, error) {
	if b == nil {
		return nil, fmt.Errorf("nil block")
	}
	header, err := convertHeader(b)
	if err != nil {
		return nil, err
	}
	txs := make([]*types.BtcTx, 0, len(b.Tx))
	for i := range b.Tx {
		tx, err := convertTx(&b.Tx[i])
		if err != nil {
			return nil, fmt.Errorf("tx[%d] %s: %w", i, b.Tx[i].Txid, err)
		}
		txs = append(txs, tx)
	}
	return &types.BtcBlockCommit{
		Header: header,
		Txs:    txs,
	}, nil
}

func convertHeader(b *btcjson.GetBlockVerboseTxResult) (*types.BtcHeader, error) {
	prev, err := decodeBigEndianHash(b.PreviousHash)
	if err != nil {
		return nil, fmt.Errorf("prev hash: %w", err)
	}
	merkle, err := decodeBigEndianHash(b.MerkleRoot)
	if err != nil {
		return nil, fmt.Errorf("merkle root: %w", err)
	}
	bits, err := strconvParseUint32Hex(b.Bits)
	if err != nil {
		return nil, fmt.Errorf("bits: %w", err)
	}
	if b.Time < 0 {
		return nil, fmt.Errorf("invalid timestamp")
	}
	if b.Version < 0 {
		return nil, fmt.Errorf("invalid version")
	}
	return &types.BtcHeader{
		Version:    uint32(b.Version),
		PrevBlock:  prev,
		MerkleRoot: merkle,
		Timestamp:  uint32(b.Time),
		Bits:       bits,
		Nonce:      uint32(b.Nonce),
	}, nil
}

func convertTx(tx *btcjson.TxRawResult) (*types.BtcTx, error) {
	txid, err := decodeBigEndianHash(tx.Txid)
	if err != nil {
		return nil, fmt.Errorf("txid: %w", err)
	}
	coinbase := len(tx.Vin) > 0 && tx.Vin[0].IsCoinBase()
	vin := make([]*types.BtcTxIn, 0, len(tx.Vin))
	for i := range tx.Vin {
		in, err := convertVin(&tx.Vin[i])
		if err != nil {
			return nil, fmt.Errorf("vin[%d]: %w", i, err)
		}
		vin = append(vin, in)
	}
	vout := make([]*types.BtcTxOut, 0, len(tx.Vout))
	for i := range tx.Vout {
		out := convertVout(&tx.Vout[i])
		vout = append(vout, out)
	}
	return &types.BtcTx{
		Txid:     txid,
		Coinbase: coinbase,
		Vin:      vin,
		Vout:     vout,
	}, nil
}

func convertVin(in *btcjson.Vin) (*types.BtcTxIn, error) {
	if in.IsCoinBase() {
		return &types.BtcTxIn{}, nil
	}
	prev, err := decodeBigEndianHash(in.Txid)
	if err != nil {
		return nil, fmt.Errorf("prev txid: %w", err)
	}
	return &types.BtcTxIn{
		PrevTxid: prev,
		PrevVout: in.Vout,
	}, nil
}

// btcToSats converts a BTC amount expressed as a float64 to integer satoshis.
// Direct truncation (uint64(v * 1e8)) loses a satoshi for values like 0.29 or
// 0.57 BTC because of IEEE 754 rounding; the slim commit feeds straight into
// merkle/PoW validation, so any per-validator divergence is a fork hazard.
func btcToSats(btc float64) uint64 {
	if btc <= 0 || math.IsNaN(btc) || math.IsInf(btc, 0) {
		return 0
	}
	return uint64(math.Round(btc * 1e8))
}

func convertVout(out *btcjson.Vout) *types.BtcTxOut {
	o := &types.BtcTxOut{
		N:    out.N,
		Sats: btcToSats(out.Value),
	}
	switch strings.ToLower(out.ScriptPubKey.Type) {
	case "nulldata":
		scriptBytes, err := hex.DecodeString(out.ScriptPubKey.Hex)
		if err != nil {
			log.Warn().Err(err).Uint32("vout", out.N).Str("script_hex", out.ScriptPubKey.Hex).Msg("failed to decode nulldata script; OP_RETURN will be empty")
			break
		}
		o.OpReturn = scriptBytes
	default:
		if out.ScriptPubKey.Address == "" {
			break
		}
		hash, err := zk.BitcoinAddressToHash160(out.ScriptPubKey.Address)
		if err != nil {
			// Address types other than P2PKH/P2WPKH (P2SH/P2WSH/P2TR/...) are
			// expected here; logging at debug avoids flooding for normal blocks.
			log.Debug().Err(err).Uint32("vout", out.N).Str("address", out.ScriptPubKey.Address).Str("type", out.ScriptPubKey.Type).Msg("unsupported output address; address will be empty")
			break
		}
		o.Address = append(o.Address, hash[:]...)
	}
	return o
}

// decodeBigEndianHash takes a Bitcoin RPC big-endian hex hash (the displayable
// form) and returns the 32-byte little-endian wire-format bytes used inside
// block headers and transaction lookups.
func decodeBigEndianHash(s string) ([]byte, error) {
	bz, err := hex.DecodeString(s)
	if err != nil {
		return nil, err
	}
	if len(bz) != 32 {
		return nil, fmt.Errorf("hash must be 32 bytes, got %d", len(bz))
	}
	return reverseBytes(bz), nil
}

func reverseBytes(b []byte) []byte {
	out := make([]byte, len(b))
	for i := range b {
		out[i] = b[len(b)-1-i]
	}
	return out
}

func strconvParseUint32Hex(h string) (uint32, error) {
	bz, err := hex.DecodeString(h)
	if err != nil {
		return 0, err
	}
	if len(bz) > 4 {
		return 0, fmt.Errorf("value too large")
	}
	var v uint32
	for _, b := range bz {
		v = (v << 8) | uint32(b)
	}
	return v, nil
}
