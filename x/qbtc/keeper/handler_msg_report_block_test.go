package keeper_test

import (
	"encoding/hex"
	"encoding/json"
	"math"
	"os"
	"strings"
	"testing"

	"github.com/btcq-org/qbtc/x/qbtc/keeper"
	"github.com/btcq-org/qbtc/x/qbtc/types"
	"github.com/btcq-org/qbtc/x/qbtc/zk"
	"github.com/btcsuite/btcd/btcjson"
	"github.com/cosmos/gogoproto/proto"
	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// reverseHexHash decodes a Bitcoin big-endian hex hash (the displayable form
// returned by RPC) and reverses it into the 32-byte little-endian wire
// representation the slim proto stores.
func reverseHexHash(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic("invalid hex hash: " + s)
	}
	out := make([]byte, len(b))
	for i := range b {
		out[i] = b[len(b)-1-i]
	}
	return out
}

// hexBigEndianTxid mirrors reverseHexHash for txid strings; kept distinct so
// callers can read tests without remembering the byte ordering subtlety.
func hexBigEndianTxid(s string) []byte { return reverseHexHash(s) }

// loadBlockCommit parses a verbose-tx JSON RPC dump and converts it into the
// slim BtcBlockCommit form qbtc consumes. Output addresses fall back to
// hash160(P2PKH/P2WPKH); other types yield an empty address. nulldata outputs
// preserve the raw OP_RETURN script bytes so the chain re-parses claim memos.
func loadBlockCommit(t *testing.T, path string) (*types.BtcBlockCommit, *btcjson.GetBlockVerboseTxResult) {
	t.Helper()
	raw, err := os.ReadFile(path)
	require.NoError(t, err)
	var b btcjson.GetBlockVerboseTxResult
	require.NoError(t, json.Unmarshal(raw, &b))

	prevBlock := make([]byte, 32)
	if b.PreviousHash != "" {
		prevBlock = reverseHexHash(b.PreviousHash)
	}
	header := &types.BtcHeader{
		Version:    uint32(b.Version),
		PrevBlock:  prevBlock,
		MerkleRoot: reverseHexHash(b.MerkleRoot),
		Timestamp:  uint32(b.Time),
		Nonce:      uint32(b.Nonce),
	}
	bitsBytes, err := hex.DecodeString(b.Bits)
	require.NoError(t, err)
	for _, x := range bitsBytes {
		header.Bits = (header.Bits << 8) | uint32(x)
	}

	txs := make([]*types.BtcTx, 0, len(b.Tx))
	for _, tx := range b.Tx {
		coinbase := len(tx.Vin) > 0 && tx.Vin[0].IsCoinBase()
		var vin []*types.BtcTxIn
		for _, in := range tx.Vin {
			if in.IsCoinBase() {
				vin = append(vin, &types.BtcTxIn{})
				continue
			}
			vin = append(vin, &types.BtcTxIn{
				PrevTxid: reverseHexHash(in.Txid),
				PrevVout: in.Vout,
			})
		}
		var vout []*types.BtcTxOut
		for _, o := range tx.Vout {
			out := &types.BtcTxOut{
				N:    o.N,
				Sats: uint64(math.Round(o.Value * 1e8)),
			}
			switch strings.ToLower(o.ScriptPubKey.Type) {
			case "nulldata":
				if scriptBytes, err := hex.DecodeString(o.ScriptPubKey.Hex); err == nil {
					out.OpReturn = scriptBytes
				}
			default:
				if o.ScriptPubKey.Address != "" {
					if h, err := zk.BitcoinAddressToHash160(o.ScriptPubKey.Address); err == nil {
						out.Address = append(out.Address, h[:]...)
					}
				}
			}
			vout = append(vout, out)
		}
		txs = append(txs, &types.BtcTx{
			Txid:     reverseHexHash(tx.Txid),
			Coinbase: coinbase,
			Vin:      vin,
			Vout:     vout,
		})
	}
	return &types.BtcBlockCommit{Header: header, Txs: txs}, &b
}

// utxoKeyFromHexTxid is a tiny convenience for stating expected UTXO keys with
// the same hex strings the original tests used.
func utxoKeyFromHexTxid(txidHex string, vout uint32) string {
	return types.UTXOKey(hexBigEndianTxid(txidHex), vout)
}

func TestSetMsgReportBlock(t *testing.T) {
	inputs := []struct {
		name      string
		fileName  string
		setup     func(st *testing.T, f *fixture)
		checkFunc func(st *testing.T, f *fixture)
	}{
		{
			name:     "block 0",
			fileName: "../../../testdata/block/1.json",
			setup:    nil,
			checkFunc: func(st *testing.T, f *fixture) {
				key := utxoKeyFromHexTxid("4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b", 0)
				utxo, err := f.keeper.Utxoes.Get(f.ctx, key)
				require.NoError(st, err)
				require.NotNil(st, utxo)
				require.Equal(st, utxo.EntitledAmount, uint64(5000000000))
			},
		},
		{
			name:     "block 923828",
			fileName: "../../../testdata/block/923828.json",
			setup: func(st *testing.T, f *fixture) {
				addr, err := zk.BitcoinAddressToHash160("1J6QsrCXRTZusGEeyg44BcoqgM4SZXTXhC")
				require.NoError(st, err)
				utxo := types.UTXO{
					Txid:           hexBigEndianTxid("714e0124f36a99799ab034629d1a3abe248dc492b7f1404467d50921d617d6f8"),
					Vout:           279,
					Amount:         2748504,
					EntitledAmount: 2748504,
					Address:        addr[:],
				}
				require.NoError(st, f.keeper.Utxoes.Set(f.ctx, utxo.GetKey(), utxo))
				utxo1 := types.UTXO{
					Txid:           hexBigEndianTxid("da31e2e6b9b8fd8c34d944d79ccf92d69bfb28823c6ec36a9118d7280cd4d315"),
					Vout:           0,
					Amount:         5433643000,
					EntitledAmount: 5433643000,
					Address:        addr[:],
				}
				require.NoError(st, f.keeper.Utxoes.Set(f.ctx, utxo1.GetKey(), utxo1))
			},
			checkFunc: func(st *testing.T, f *fixture) {
				_, err := f.keeper.Utxoes.Get(f.ctx, utxoKeyFromHexTxid("8eb9d5922df115ccea20adf84f2b1e6664fd9a2c196a3f863303283353d52a33", 0))
				require.Error(st, err)
				coinbaseKey := utxoKeyFromHexTxid("7025015c9a362d21ac2731bcad2f0ef6c7bb9a1a7bf297c443eb53e952beb8dd", 1)
				utxo, err := f.keeper.Utxoes.Get(f.ctx, coinbaseKey)
				require.NoError(st, err)
				require.NotNil(st, utxo)
				require.Equal(st, utxo.EntitledAmount, uint64(313462452))
			},
		},
		{
			name:     "block 300003",
			fileName: "../../../testdata/block/300003.json",
			setup:    nil,
			checkFunc: func(st *testing.T, f *fixture) {
				coinbaseKey := utxoKeyFromHexTxid("effbacb359a68252c25d349cea55eaff68ef549aef6aef0faa30e38ab48080a3", 0)
				utxo, err := f.keeper.Utxoes.Get(f.ctx, coinbaseKey)
				require.NoError(st, err)
				require.NotNil(st, utxo)
				require.Equal(st, uint64(2502676489), utxo.EntitledAmount)

				key1 := utxoKeyFromHexTxid("e8bd07a2b2a68965ef732d6dad74d3af16ac384aff1c92a42e1707f5bc8fb714", 0)
				utxo1, err := f.keeper.Utxoes.Get(f.ctx, key1)
				require.NoError(st, err)
				require.NotNil(st, utxo1)
				require.Equal(st, uint64(0), utxo1.EntitledAmount)
			},
		},
		{
			name:     "block 300003 with preload utxos",
			fileName: "../../../testdata/block/300003.json",
			setup: func(st *testing.T, f *fixture) {
				addr, err := zk.BitcoinAddressToHash160("1J6QsrCXRTZusGEeyg44BcoqgM4SZXTXhC")
				require.NoError(st, err)
				utxo := types.UTXO{
					Txid:           hexBigEndianTxid("c99a1454100bc1a57ff5206dcfcaf196907f5724417d9e0a496741949fe0d20d"),
					Vout:           963,
					Amount:         53048210,
					EntitledAmount: 53048210,
					Address:        addr[:],
				}
				require.NoError(st, f.keeper.Utxoes.Set(f.ctx, utxo.GetKey(), utxo))
			},
			checkFunc: func(st *testing.T, f *fixture) {
				coinbaseKey := utxoKeyFromHexTxid("effbacb359a68252c25d349cea55eaff68ef549aef6aef0faa30e38ab48080a3", 0)
				utxo, err := f.keeper.Utxoes.Get(f.ctx, coinbaseKey)
				require.NoError(st, err)
				require.NotNil(st, utxo)
				require.Equal(st, uint64(2502666489), utxo.EntitledAmount)

				key1 := utxoKeyFromHexTxid("2bda3732778da19cbf8799aceed3a6ab270948aeac85678bee013ddf3070687e", 0)
				utxo1, err := f.keeper.Utxoes.Get(f.ctx, key1)
				require.NoError(st, err)
				require.NotNil(st, utxo1)
				require.Equal(st, uint64(20000000), utxo1.EntitledAmount)

				key2 := utxoKeyFromHexTxid("2bda3732778da19cbf8799aceed3a6ab270948aeac85678bee013ddf3070687e", 1)
				utxo2, err := f.keeper.Utxoes.Get(f.ctx, key2)
				require.NoError(st, err)
				require.NotNil(st, utxo2)
				require.Equal(st, uint64(33038210), utxo2.EntitledAmount)
			},
		},
		{
			name:     "block 300003 with partial claimed utxos",
			fileName: "../../../testdata/block/300003.json",
			setup: func(st *testing.T, f *fixture) {
				addr, err := zk.BitcoinAddressToHash160("1J6QsrCXRTZusGEeyg44BcoqgM4SZXTXhC")
				require.NoError(st, err)
				preload := []types.UTXO{
					{
						Txid:           hexBigEndianTxid("d510799f177184922edfb98adcc023b1f13d087c2bad700798972f0defcffdca"),
						Vout:           1,
						Amount:         9494012,
						EntitledAmount: 9494012,
						Address:        addr[:],
					},
					{
						Txid:           hexBigEndianTxid("b66a7f1e6e9030cecf87a0d450f257857c34de737934fc013be8ebe76982e20c"),
						Vout:           1,
						Amount:         13766651,
						EntitledAmount: 13766651,
						Address:        addr[:],
					},
					{
						Txid:           hexBigEndianTxid("bc84b6ec6473499eb9c5cbd266cc17dfb177efe2a35c9da843b884106be829aa"),
						Vout:           0,
						Amount:         11825990,
						EntitledAmount: 0,
						Address:        addr[:],
					},
				}
				for _, u := range preload {
					require.NoError(st, f.keeper.Utxoes.Set(f.ctx, u.GetKey(), u))
				}
			},
			checkFunc: func(st *testing.T, f *fixture) {
				coinbaseKey := utxoKeyFromHexTxid("effbacb359a68252c25d349cea55eaff68ef549aef6aef0faa30e38ab48080a3", 0)
				utxo, err := f.keeper.Utxoes.Get(f.ctx, coinbaseKey)
				require.NoError(st, err)
				require.NotNil(st, utxo)
				require.Equal(st, uint64(2502666489), utxo.EntitledAmount)

				key1 := utxoKeyFromHexTxid("bfa3ed4869f33192946dcc03d7789d6be32aa07f083e9752fcea2a5568a9ea47", 0)
				utxo1, err := f.keeper.Utxoes.Get(f.ctx, key1)
				require.NoError(st, err)
				require.NotNil(st, utxo1)
				require.Equal(st, uint64(14659050), utxo1.EntitledAmount)

				key2 := utxoKeyFromHexTxid("bfa3ed4869f33192946dcc03d7789d6be32aa07f083e9752fcea2a5568a9ea47", 1)
				utxo2, err := f.keeper.Utxoes.Get(f.ctx, key2)
				require.NoError(st, err)
				require.NotNil(st, utxo2)
				require.Equal(st, uint64(8591612), utxo2.EntitledAmount)
			},
		},
	}
	for _, tc := range inputs {
		t.Run(tc.name, func(st *testing.T) {
			f := initFixture(st)

			commit, _ := loadBlockCommit(st, tc.fileName)

			// Anchor the prev-hash chain so the report passes header validation.
			require.NoError(st, f.keeper.LastProcessedHeader.Set(f.ctx, commit.Header.PrevBlock))

			commitBytes, err := proto.Marshal(commit)
			require.NoError(st, err)
			signature, err := f.privateKey.Sign(commitBytes)
			require.NoError(st, err)

			headerHash, err := keeper.HeaderHash(commit.Header)
			require.NoError(st, err)

			address, err := f.GetConsensusAddress()
			assert.Nil(st, err)
			signerAddr, err := f.GetRandomQbtcAddress()
			assert.NoError(st, err)
			msg := &types.MsgBtcBlock{
				Hash:   headerHash[:],
				Commit: commit,
				Attestations: []*types.Attestation{
					{Address: address, Signature: signature},
				},
				Signer: signerAddr,
			}
			if tc.setup != nil {
				tc.setup(st, f)
			}

			server := keeper.NewMsgServerImpl(f.keeper)
			_, err = server.SetMsgReportBlock(f.ctx, msg)
			assert.NoError(st, err)
			tc.checkFunc(st, f)
		})
	}
}

// TestSetMsgReportBlock_WithClaim builds a synthetic regtest-style block (max
// target bits, easy PoW) containing a claim tx. The chain validates header,
// PoW, merkle root, and prev-hash linkage, then processes the claim.
func TestSetMsgReportBlock_WithClaim(t *testing.T) {
	f := initFixture(t)
	f.bankKeeper.EXPECT().MintCoins(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil).AnyTimes()
	f.bankKeeper.EXPECT().SendCoinsFromModuleToAccount(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(nil).AnyTimes()

	addr, err := zk.BitcoinAddressToHash160("13qCVr4a2ryEkM8fA3r85QzWFqMNV7p3nB")
	require.NoError(t, err)
	parentTxid := hexBigEndianTxid("dbdd7837a8f7e113f6038b6cf659600538c53b7a742e2b9b1f22de3039e912ba")
	utxoToClaim := types.UTXO{
		Txid:           parentTxid,
		Vout:           0,
		Amount:         88109900000,
		EntitledAmount: 88109900000,
		Address:        addr[:],
	}
	require.NoError(t, f.keeper.Utxoes.Set(f.ctx, utxoToClaim.GetKey(), utxoToClaim))

	claimerAddr, err := f.GetRandomQbtcAddress()
	require.NoError(t, err)

	// claim tx: spends parentTxid:0 to itself with an OP_RETURN "claim:<addr>"
	claimMemo := []byte("claim:" + claimerAddr)
	opReturn := append([]byte{0x6a, byte(len(claimMemo))}, claimMemo...)
	claimTxid := make([]byte, 32)
	for i := range claimTxid {
		claimTxid[i] = 0xab
	}
	coinbaseTxid := make([]byte, 32)
	for i := range coinbaseTxid {
		coinbaseTxid[i] = 0xcd
	}
	commit := &types.BtcBlockCommit{
		Txs: []*types.BtcTx{
			{
				Txid:     coinbaseTxid,
				Coinbase: true,
				Vin:      []*types.BtcTxIn{{}},
				Vout: []*types.BtcTxOut{
					{N: 0, Sats: 5000000000, Address: addr[:]},
				},
			},
			{
				Txid:     claimTxid,
				Coinbase: false,
				Vin:      []*types.BtcTxIn{{PrevTxid: parentTxid, PrevVout: 0}},
				Vout: []*types.BtcTxOut{
					{N: 0, Sats: 88000000000, Address: addr[:]},
					{N: 1, Sats: 0, OpReturn: opReturn},
				},
			},
		},
	}
	merkle, err := keeper.MerkleRoot([][]byte{coinbaseTxid, claimTxid})
	require.NoError(t, err)

	prev := make([]byte, 32)
	require.NoError(t, f.keeper.LastProcessedHeader.Set(f.ctx, prev))

	// Relax the PoW ceiling so a synthetic block at regtest difficulty
	// passes header validation. Production keepers default to
	// MainnetPowLimitBits; tests that build fabricated commits must lower it.
	f.keeper.PoWLimitBits = 0x207fffff

	header := &types.BtcHeader{
		Version:    1,
		PrevBlock:  prev,
		MerkleRoot: merkle[:],
		Timestamp:  1,
		Bits:       0x207fffff, // regtest max target
		Nonce:      0,
	}
	// Tiny PoW search; with regtest target ~50% of nonces satisfy.
	var headerHash [32]byte
	for {
		headerHash, err = keeper.HeaderHash(header)
		require.NoError(t, err)
		if keeper.CheckProofOfWork(headerHash, header.Bits, f.keeper.PoWLimitBits) == nil {
			break
		}
		header.Nonce++
	}
	commit.Header = header

	commitBytes, err := proto.Marshal(commit)
	require.NoError(t, err)
	signature, err := f.privateKey.Sign(commitBytes)
	require.NoError(t, err)

	address, err := f.GetConsensusAddress()
	require.NoError(t, err)
	signerAddr, err := f.GetRandomQbtcAddress()
	require.NoError(t, err)
	msg := &types.MsgBtcBlock{
		Hash:   headerHash[:],
		Commit: commit,
		Attestations: []*types.Attestation{
			{Address: address, Signature: signature},
		},
		Signer: signerAddr,
	}

	server := keeper.NewMsgServerImpl(f.keeper)
	_, err = server.SetMsgReportBlock(f.ctx, msg)
	assert.NoError(t, err)

	utxoAfterClaim, err := f.keeper.Utxoes.Get(f.ctx, types.UTXOKey(claimTxid, 0))
	assert.NoError(t, err)
	assert.Equal(t, uint64(0), utxoAfterClaim.EntitledAmount)
}
