package keeper_test

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/btcsuite/btcd/blockchain"
	"github.com/btcsuite/btcd/btcjson"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/stretchr/testify/require"

	"github.com/btcq-org/qbtc/x/qbtc/keeper"
	"github.com/btcq-org/qbtc/x/qbtc/types"
)

// testPkHash is the hash160 that test outputs pay to.
var testPkHash = bytes.Repeat([]byte{0x88}, 20)

// testAddress returns the P2PKH address of testPkHash on the given network.
func testAddress(t *testing.T, params *chaincfg.Params) string {
	t.Helper()
	addr, err := btcutil.NewAddressPubKeyHash(testPkHash, params)
	require.NoError(t, err)
	return addr.EncodeAddress()
}

// p2pkhOut is an output of sats to testPkHash.
func p2pkhOut(t *testing.T, sats int64) *wire.TxOut {
	t.Helper()
	script, err := txscript.NewScriptBuilder().AddOp(txscript.OP_DUP).AddOp(txscript.OP_HASH160).
		AddData(testPkHash).AddOp(txscript.OP_EQUALVERIFY).AddOp(txscript.OP_CHECKSIG).Script()
	require.NoError(t, err)
	return wire.NewTxOut(sats, script)
}

// claimMemoOut is a zero-value OP_RETURN output carrying "claim:<qbtcAddr>".
func claimMemoOut(t *testing.T, qbtcAddr string) *wire.TxOut {
	t.Helper()
	script, err := txscript.NullDataScript([]byte("claim:" + qbtcAddr))
	require.NoError(t, err)
	return wire.NewTxOut(0, script)
}

// outpoint returns the outpoint of output n of the transaction with the given txid.
func outpoint(t *testing.T, txid string, n uint32) wire.OutPoint {
	t.Helper()
	hash, err := chainhash.NewHashFromStr(txid)
	require.NoError(t, err)
	return *wire.NewOutPoint(hash, n)
}

// spendTx spends the given outpoints into outs.
func spendTx(ins []wire.OutPoint, outs ...*wire.TxOut) *wire.MsgTx {
	tx := wire.NewMsgTx(2)
	for i := range ins {
		tx.AddTxIn(wire.NewTxIn(&ins[i], nil, nil))
	}
	for _, out := range outs {
		tx.AddTxOut(out)
	}
	return tx
}

// setTestUtxo preloads a UTXO paying to testPkHash on the given network.
func setTestUtxo(t *testing.T, f *fixture, params *chaincfg.Params, txid string, vout uint32, amount, entitled uint64) {
	t.Helper()
	utxo := types.UTXO{
		Txid:           txid,
		Vout:           vout,
		Amount:         amount,
		EntitledAmount: entitled,
		ScriptPubKey: &types.ScriptPubKeyResult{
			Hex:     hex.EncodeToString(p2pkhOut(t, 0).PkScript),
			Type:    "pubkeyhash",
			Address: testAddress(t, params),
		},
	}
	require.NoError(t, f.keeper.Utxoes.Set(f.ctx, utxo.GetKey(), utxo))
}

func getTestEntitlement(t *testing.T, f *fixture, txid string, vout uint32) uint64 {
	t.Helper()
	utxo, err := f.keeper.Utxoes.Get(f.ctx, fmt.Sprintf("%s-%d", txid, vout))
	require.NoError(t, err)
	return utxo.EntitledAmount
}

func getLastProcessed(t *testing.T, f *fixture) uint64 {
	t.Helper()
	h, err := f.keeper.GetLastProcessedBlock(f.ctx)
	require.NoError(t, err)
	return h
}

// setBtcAnchor stores header as the tip at height, as InitGenesis does.
func setBtcAnchor(t *testing.T, f *fixture, height uint64, header *wire.BlockHeader) {
	t.Helper()
	var buf bytes.Buffer
	require.NoError(t, header.Serialize(&buf))
	require.NoError(t, f.keeper.BtcTipHeader.Set(f.ctx, buf.Bytes()))
	require.NoError(t, f.keeper.BtcPeriodStartTime.Set(f.ctx, uint64(header.Timestamp.Unix())))
	require.NoError(t, f.keeper.LastProcessedBlock.Set(f.ctx, height))
}

// attestedBlockMsg returns the MsgBtcBlock for block at height, attested by
// the fixture's only validator and signed by the injection signer.
func attestedBlockMsg(t *testing.T, f *fixture, height uint64, block *wire.MsgBlock) *types.MsgBtcBlock {
	t.Helper()
	commit, err := types.NewBtcBlockCommit(block)
	require.NoError(t, err)
	signBytes, content, err := types.EncodeBtcBlockCommit(commit)
	require.NoError(t, err)
	address, err := f.GetConsensusAddress()
	require.NoError(t, err)
	signature, err := f.privateKey.Sign(signBytes)
	require.NoError(t, err)
	return &types.MsgBtcBlock{
		Height:       height,
		Hash:         block.BlockHash().String(),
		BlockContent: content,
		Attestations: []*types.Attestation{{Address: address, Signature: signature}},
		Signer:       types.EBifrostSignerAddress,
	}
}

func submitBlockMsg(f *fixture, msg *types.MsgBtcBlock) error {
	_, err := keeper.NewMsgServerImpl(f.keeper).SetMsgReportBlock(f.ctx, msg)
	return err
}

// regtestChain mines regtest blocks on top of a stored anchor.
type regtestChain struct {
	t      *testing.T
	f      *fixture
	params *chaincfg.Params
	tip    wire.BlockHeader
	height uint64
}

// newRegtestChain switches the fixture's keeper to regtest rules and anchors it
// at a mined regtest block at height.
func newRegtestChain(t *testing.T, f *fixture, height uint64) *regtestChain {
	t.Helper()
	c := &regtestChain{t: t, f: f, params: &chaincfg.RegressionNetParams, height: height}
	f.keeper.SetBtcParamsForTesting(c.params)
	c.tip = wire.BlockHeader{
		Version:   4,
		Timestamp: time.Unix(1_700_000_000, 0),
		Bits:      c.params.PowLimitBits,
	}
	mineHeader(t, &c.tip, c.params)
	setBtcAnchor(t, f, height, &c.tip)
	return c
}

// mineHeader sets the nonce so the header meets its target.
func mineHeader(t *testing.T, header *wire.BlockHeader, params *chaincfg.Params) {
	t.Helper()
	target := blockchain.CompactToBig(header.Bits)
	for nonce := uint32(0); nonce < 1<<20; nonce++ {
		header.Nonce = nonce
		hash := header.BlockHash()
		if blockchain.HashToBig(&hash).Cmp(target) <= 0 {
			return
		}
	}
	t.Fatal("could not mine regtest header")
}

// coinbase is a coinbase for the next block with one output per amount; with
// no amounts it has a single zero-value output, which creates no UTXO.
func (c *regtestChain) coinbase(amounts ...int64) *wire.MsgTx {
	sigScript, err := txscript.NewScriptBuilder().AddInt64(int64(c.height + 1)).AddData([]byte("qbtc-test")).Script()
	require.NoError(c.t, err)
	tx := wire.NewMsgTx(2)
	tx.AddTxIn(wire.NewTxIn(wire.NewOutPoint(&chainhash.Hash{}, wire.MaxPrevOutIndex), sigScript, nil))
	if len(amounts) == 0 {
		amounts = []int64{0}
	}
	for _, sats := range amounts {
		tx.AddTxOut(p2pkhOut(c.t, sats))
	}
	return tx
}

// nextBlock mines the next block with the given transactions, which must
// start with a coinbase. It does not submit it.
func (c *regtestChain) nextBlock(txs ...*wire.MsgTx) *wire.MsgBlock {
	block := wire.NewMsgBlock(&wire.BlockHeader{
		Version:   4,
		PrevBlock: c.tip.BlockHash(),
		Timestamp: c.tip.Timestamp.Add(10 * time.Minute),
		Bits:      c.params.PowLimitBits,
	})
	utxs := make([]*btcutil.Tx, len(txs))
	for i, tx := range txs {
		require.NoError(c.t, block.AddTransaction(tx))
		utxs[i] = btcutil.NewTx(tx)
	}
	block.Header.MerkleRoot = blockchain.CalcMerkleRoot(utxs, false)
	mineHeader(c.t, &block.Header, c.params)
	return block
}

// submit reports block as the next height and, if it is accepted, makes it
// the tip.
func (c *regtestChain) submit(block *wire.MsgBlock) error {
	if err := submitBlockMsg(c.f, attestedBlockMsg(c.t, c.f, c.height+1, block)); err != nil {
		return err
	}
	c.tip = block.Header
	c.height++
	return nil
}

func (c *regtestChain) mustSubmit(block *wire.MsgBlock) {
	c.t.Helper()
	require.NoError(c.t, c.submit(block))
}

// loadMainnetBlock rebuilds a real mainnet block from a getblock (verbosity 2)
// JSON fixture, and checks that its header hashes to the fixture's hash.
func loadMainnetBlock(t *testing.T, file string) (*wire.MsgBlock, uint64) {
	t.Helper()
	raw, err := os.ReadFile(file)
	require.NoError(t, err)
	var blk btcjson.GetBlockVerboseTxResult
	require.NoError(t, json.Unmarshal(raw, &blk))
	bits, err := strconv.ParseUint(blk.Bits, 16, 32)
	require.NoError(t, err)
	prev, err := chainhash.NewHashFromStr(blk.PreviousHash)
	require.NoError(t, err)
	merkle, err := chainhash.NewHashFromStr(blk.MerkleRoot)
	require.NoError(t, err)
	block := wire.NewMsgBlock(&wire.BlockHeader{
		Version:    blk.Version,
		PrevBlock:  *prev,
		MerkleRoot: *merkle,
		Timestamp:  time.Unix(blk.Time, 0),
		Bits:       uint32(bits),
		Nonce:      blk.Nonce,
	})
	require.Equal(t, blk.Hash, block.BlockHash().String())
	for _, tx := range blk.Tx {
		txBytes, err := hex.DecodeString(tx.Hex)
		require.NoError(t, err)
		msgTx := new(wire.MsgTx)
		require.NoError(t, msgTx.Deserialize(bytes.NewReader(txBytes)))
		require.Equal(t, tx.Txid, msgTx.TxHash().String())
		require.NoError(t, block.AddTransaction(msgTx))
	}
	return block, uint64(blk.Height)
}

// mainnetHeader decodes a serialized 80-byte header from hex.
func mainnetHeader(t *testing.T, headerHex string) *wire.BlockHeader {
	t.Helper()
	raw, err := hex.DecodeString(headerHex)
	require.NoError(t, err)
	var header wire.BlockHeader
	require.NoError(t, header.Deserialize(bytes.NewReader(raw)))
	return &header
}

// Real mainnet headers of the blocks before the JSON fixtures.
const (
	mainnetHeader300002 = "02000000a9ab12e32ceddc2ba5e6ad651fac772c9836df834d91a0490000000000000000df7575c78f831f20af147ea754e584aad959656969632da978d2dd718623fd30c5cc6d536c890019e65107e9"
	mainnetHeader923827 = "006025230a17ebc74842319cf87925ad47b517a1951832760aa000000000000000000000ecc1a07ffaae157b36902d49bff2244308ef8697c12f144a4cf790bff0a2e5872845196936d901176086e99b"
)
