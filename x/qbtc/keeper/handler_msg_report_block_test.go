package keeper_test

import (
	"compress/gzip"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"testing"

	"cosmossdk.io/collections"
	sdkmath "cosmossdk.io/math"
	"github.com/btcq-org/qbtc/x/qbtc/keeper"
	"github.com/btcq-org/qbtc/x/qbtc/types"
	"github.com/btcsuite/btcd/btcjson"
	"github.com/btcsuite/btcd/btcutil"
	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSetMsgReportBlock(t *testing.T) {
	inputs := []struct {
		name      string
		fileName  string
		blockHash string
		height    uint64
		setup     func(st *testing.T, f *fixture)
		checkFunc func(st *testing.T, f *fixture)
	}{
		{
			name:      "block 0",
			height:    0,
			blockHash: "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f",
			fileName:  "../../../testdata/block/1.json",
			setup:     nil,
			checkFunc: func(st *testing.T, f *fixture) {
				// make sure coinbase UTXO is created
				key := "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b-0"
				utxo, err := f.keeper.Utxoes.Get(f.ctx, key)
				require.NoError(st, err)
				require.NotNil(st, utxo)
				require.Equal(st, utxo.EntitledAmount, uint64(5000000000))
			},
		},
		{
			name:      "block 923828",
			height:    923828,
			blockHash: "00000000000000000000dddb246d85ece1541da3cf95e5044def6b2f7d733a0d",
			fileName:  "../../../testdata/block/923828.json",
			setup: func(st *testing.T, f *fixture) {
				key := "714e0124f36a99799ab034629d1a3abe248dc492b7f1404467d50921d617d6f8-279"
				utxo := types.UTXO{
					Txid:           "714e0124f36a99799ab034629d1a3abe248dc492b7f1404467d50921d617d6f8",
					Vout:           279,
					Amount:         2748504,
					EntitledAmount: 2748504,
					ScriptPubKey: &types.ScriptPubKeyResult{
						Hex:     "76a91488ac",
						Type:    "pubkeyhash",
						Address: "1J6QsrCXRTZusGEeyg44BcoqgM4SZXTXhC",
					},
				}
				err := f.keeper.Utxoes.Set(f.ctx, key, utxo)
				require.NoError(st, err)
				key1 := "da31e2e6b9b8fd8c34d944d79ccf92d69bfb28823c6ec36a9118d7280cd4d315-0"
				utxo1 := types.UTXO{
					Txid:           "da31e2e6b9b8fd8c34d944d79ccf92d69bfb28823c6ec36a9118d7280cd4d315",
					Vout:           0,
					Amount:         5433643000,
					EntitledAmount: 5433643000,
					ScriptPubKey: &types.ScriptPubKeyResult{
						Hex:     "76a91488ac",
						Type:    "pubkeyhash",
						Address: "1J6QsrCXRTZusGEeyg44BcoqgM4SZXTXhC",
					},
				}
				err = f.keeper.Utxoes.Set(f.ctx, key1, utxo1)
				require.NoError(st, err)
			},
			checkFunc: func(st *testing.T, f *fixture) {
				key := "8eb9d5922df115ccea20adf84f2b1e6664fd9a2c196a3f863303283353d52a33-0"
				_, err := f.keeper.Utxoes.Get(f.ctx, key)
				require.Error(st, err)
				// make sure coinbase UTXO has deducted the fee
				coinbaseKey := "7025015c9a362d21ac2731bcad2f0ef6c7bb9a1a7bf297c443eb53e952beb8dd-1"
				utxo, err := f.keeper.Utxoes.Get(f.ctx, coinbaseKey)
				require.NoError(st, err)
				require.NotNil(st, utxo)
				// exact fee for this block is 65602 sats; the pre-fix truncating
				// conversion accumulated 133 extra satoshis of fee
				require.Equal(st, utxo.EntitledAmount, uint64(313461906))

			},
		},
		{
			name:      "block 300003",
			height:    300003,
			blockHash: "000000000000000082aee4ff546c1db5e1aa5f9bfbaa0c76300a792b3e91fce7",
			fileName:  "../../../testdata/block/300003.json",
			setup:     nil,
			checkFunc: func(st *testing.T, f *fixture) {
				// since we didn't preload utxos , so all the utxo is spent , which means
				coinbaseKey := "effbacb359a68252c25d349cea55eaff68ef549aef6aef0faa30e38ab48080a3-0"
				utxo, err := f.keeper.Utxoes.Get(f.ctx, coinbaseKey)
				require.NoError(st, err)
				require.NotNil(st, utxo)
				require.Equal(st, uint64(2502676489), utxo.EntitledAmount)

				key1 := "e8bd07a2b2a68965ef732d6dad74d3af16ac384aff1c92a42e1707f5bc8fb714-0"
				utxo1, err := f.keeper.Utxoes.Get(f.ctx, key1)
				require.NoError(st, err)
				require.NotNil(st, utxo1)
				require.Equal(st, uint64(0), utxo1.EntitledAmount)
			},
		},
		{
			name:      "block 300003 with preload utxos",
			height:    300003,
			blockHash: "000000000000000082aee4ff546c1db5e1aa5f9bfbaa0c76300a792b3e91fce7",
			fileName:  "../../../testdata/block/300003.json",
			setup: func(st *testing.T, f *fixture) {
				key := "c99a1454100bc1a57ff5206dcfcaf196907f5724417d9e0a496741949fe0d20d-963"
				utxo := types.UTXO{
					Txid:           "c99a1454100bc1a57ff5206dcfcaf196907f5724417d9e0a496741949fe0d20d",
					Vout:           963,
					Amount:         53048210,
					EntitledAmount: 53048210,
					ScriptPubKey: &types.ScriptPubKeyResult{
						Hex:     "76a91488ac",
						Type:    "pubkeyhash",
						Address: "1J6QsrCXRTZusGEeyg44BcoqgM4SZXTXhC",
					},
				}
				err := f.keeper.Utxoes.Set(f.ctx, key, utxo)
				require.NoError(st, err)
			},
			checkFunc: func(st *testing.T, f *fixture) {
				// since we didn't preload utxos , so all the utxo is spent , which means
				coinbaseKey := "effbacb359a68252c25d349cea55eaff68ef549aef6aef0faa30e38ab48080a3-0"
				utxo, err := f.keeper.Utxoes.Get(f.ctx, coinbaseKey)
				require.NoError(st, err)
				require.NotNil(st, utxo)
				require.Equal(st, uint64(2502666489), utxo.EntitledAmount)

				key1 := "2bda3732778da19cbf8799aceed3a6ab270948aeac85678bee013ddf3070687e-0"
				utxo1, err := f.keeper.Utxoes.Get(f.ctx, key1)
				require.NoError(st, err)
				require.NotNil(st, utxo1)

				require.Equal(st, uint64(20000000), utxo1.EntitledAmount)

				key2 := "2bda3732778da19cbf8799aceed3a6ab270948aeac85678bee013ddf3070687e-1"
				utxo2, err := f.keeper.Utxoes.Get(f.ctx, key2)
				require.NoError(st, err)
				require.NotNil(st, utxo2)
				require.Equal(st, uint64(33038210), utxo2.EntitledAmount)
			},
		},
		{
			name:      "block 300003 with partial claimed utxos",
			height:    300003,
			blockHash: "000000000000000082aee4ff546c1db5e1aa5f9bfbaa0c76300a792b3e91fce7",
			fileName:  "../../../testdata/block/300003.json",
			setup: func(st *testing.T, f *fixture) {
				key := "d510799f177184922edfb98adcc023b1f13d087c2bad700798972f0defcffdca-1"
				utxo := types.UTXO{
					Txid:           "d510799f177184922edfb98adcc023b1f13d087c2bad700798972f0defcffdca",
					Vout:           1,
					Amount:         9494012,
					EntitledAmount: 9494012,
					ScriptPubKey: &types.ScriptPubKeyResult{
						Hex:     "76a91488ac",
						Type:    "pubkeyhash",
						Address: "1J6QsrCXRTZusGEeyg44BcoqgM4SZXTXhC",
					},
				}
				require.NoError(st, f.keeper.Utxoes.Set(f.ctx, key, utxo))

				key1 := "b66a7f1e6e9030cecf87a0d450f257857c34de737934fc013be8ebe76982e20c-1"
				utxo1 := types.UTXO{
					Txid:           "b66a7f1e6e9030cecf87a0d450f257857c34de737934fc013be8ebe76982e20c",
					Vout:           1,
					Amount:         13766651,
					EntitledAmount: 13766651,
					ScriptPubKey: &types.ScriptPubKeyResult{
						Hex:     "76a91488ac",
						Type:    "pubkeyhash",
						Address: "1J6QsrCXRTZusGEeyg44BcoqgM4SZXTXhC",
					},
				}
				require.NoError(st, f.keeper.Utxoes.Set(f.ctx, key1, utxo1))

				key2 := "bc84b6ec6473499eb9c5cbd266cc17dfb177efe2a35c9da843b884106be829aa-0"
				utxo2 := types.UTXO{
					Txid:           "bc84b6ec6473499eb9c5cbd266cc17dfb177efe2a35c9da843b884106be829aa",
					Vout:           0,
					Amount:         11825990,
					EntitledAmount: 0,
					ScriptPubKey: &types.ScriptPubKeyResult{
						Hex:     "76a91488ac",
						Type:    "pubkeyhash",
						Address: "1J6QsrCXRTZusGEeyg44BcoqgM4SZXTXhC",
					},
				}
				require.NoError(st, f.keeper.Utxoes.Set(f.ctx, key2, utxo2))
			},
			checkFunc: func(st *testing.T, f *fixture) {
				// since we didn't preload utxos , so all the utxo is spent , which means
				coinbaseKey := "effbacb359a68252c25d349cea55eaff68ef549aef6aef0faa30e38ab48080a3-0"
				utxo, err := f.keeper.Utxoes.Get(f.ctx, coinbaseKey)
				require.NoError(st, err)
				require.NotNil(st, utxo)
				require.Equal(st, uint64(2502666489), utxo.EntitledAmount)

				key1 := "bfa3ed4869f33192946dcc03d7789d6be32aa07f083e9752fcea2a5568a9ea47-0"
				utxo1, err := f.keeper.Utxoes.Get(f.ctx, key1)
				require.NoError(st, err)
				require.NotNil(st, utxo1)
				require.Equal(st, uint64(14659050), utxo1.EntitledAmount)

				key2 := "bfa3ed4869f33192946dcc03d7789d6be32aa07f083e9752fcea2a5568a9ea47-1"
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
			fileContent, err := os.ReadFile(tc.fileName)
			assert.Nil(st, err)
			compressedContent, err := types.GzipDeterministic(fileContent, gzip.BestCompression)
			assert.Nil(st, err, "failed to compress block data")
			address, err := f.GetConsensusAddress()
			assert.Nil(st, err)
			signature, err := f.privateKey.Sign(compressedContent)
			assert.Nil(st, err, "failed to sign compressed data")
			msg := &types.MsgBtcBlock{
				Height:       tc.height,
				Hash:         tc.blockHash,
				BlockContent: compressedContent,
				Attestations: []*types.Attestation{
					{
						Address:   address,
						Signature: signature,
					},
				},
				Signer: types.EBifrostSignerAddress,
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
func TestSetMsgReportBlock_WithClaim(t *testing.T) {
	f := initFixture(t)
	f.bankKeeper.EXPECT().MintCoins(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil).AnyTimes()
	f.bankKeeper.EXPECT().SendCoinsFromModuleToAccount(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(nil).AnyTimes()
	fileContent, err := os.ReadFile("../../../testdata/block/withclaim.json")
	assert.Nil(t, err)
	compressedContent, err := types.GzipDeterministic(fileContent, gzip.BestCompression)
	assert.Nil(t, err, "failed to compress block data")
	address, err := f.GetConsensusAddress()
	assert.Nil(t, err)
	signature, err := f.privateKey.Sign(compressedContent)
	assert.Nil(t, err, "failed to sign compressed data")
	msg := &types.MsgBtcBlock{
		Height:       300003,
		Hash:         "000000000000000082aee4ff546c1db5e1aa5f9bfbaa0c76300a792b3e91fce7",
		BlockContent: compressedContent,
		Attestations: []*types.Attestation{
			{
				Address:   address,
				Signature: signature,
			},
		},
		Signer: types.EBifrostSignerAddress,
	}
	// preload utxo to be claimed
	utxoToClaim := types.UTXO{
		Txid:           "dbdd7837a8f7e113f6038b6cf659600538c53b7a742e2b9b1f22de3039e912ba",
		Vout:           0,
		Amount:         88109900000,
		EntitledAmount: 88109900000,
		ScriptPubKey: &types.ScriptPubKeyResult{
			Hex:     "76a9144eb2d3adc8a627687d62e13a56df89bc777ffc8988ac",
			Type:    "pubkeyhash",
			Address: "13qCVr4a2ryEkM8fA3r85QzWFqMNV7p3nB",
		},
	}
	key := utxoToClaim.GetKey()
	assert.NoError(t, f.keeper.Utxoes.Set(f.ctx, key, utxoToClaim))
	server := keeper.NewMsgServerImpl(f.keeper)
	_, err = server.SetMsgReportBlock(f.ctx, msg)
	assert.NoError(t, err)

	utxoAfterClaim, err := f.keeper.Utxoes.Get(f.ctx, "e8bd07a2b2a68965ef732d6dad74d3af16ac384aff1c92a42e1707f5bc8fb714-0")
	assert.NoError(t, err)
	assert.Equal(t, uint64(0), utxoAfterClaim.EntitledAmount)
	// check claimed utxo
}

const testUtxoAddress = "1J6QsrCXRTZusGEeyg44BcoqgM4SZXTXhC"

func testVout(n uint32, sats int64) btcjson.Vout {
	return btcjson.Vout{
		Value: btcutil.Amount(sats).ToBTC(),
		N:     n,
		ScriptPubKey: btcjson.ScriptPubKeyResult{
			Hex:     "76a91488ac",
			Type:    "pubkeyhash",
			Address: testUtxoAddress,
		},
	}
}

func testClaimMemoVout(n uint32, qbtcAddr string) btcjson.Vout {
	return btcjson.Vout{
		N: n,
		ScriptPubKey: btcjson.ScriptPubKeyResult{
			Asm:  "OP_RETURN " + hex.EncodeToString([]byte("claim:"+qbtcAddr)),
			Type: "nulldata",
		},
	}
}

func setTestUtxo(t *testing.T, f *fixture, txid string, vout uint32, amount, entitled uint64) {
	utxo := types.UTXO{
		Txid:           txid,
		Vout:           vout,
		Amount:         amount,
		EntitledAmount: entitled,
		ScriptPubKey: &types.ScriptPubKeyResult{
			Hex:     "76a91488ac",
			Type:    "pubkeyhash",
			Address: testUtxoAddress,
		},
	}
	require.NoError(t, f.keeper.Utxoes.Set(f.ctx, utxo.GetKey(), utxo))
}

func getTestEntitlement(t *testing.T, f *fixture, txid string, vout uint32) uint64 {
	utxo, err := f.keeper.Utxoes.Get(f.ctx, fmt.Sprintf("%s-%d", txid, vout))
	require.NoError(t, err)
	return utxo.EntitledAmount
}

// submitTestBlock builds a block from txs, attests it with the fixture validator and processes it.
func submitTestBlock(t *testing.T, f *fixture, height uint64, txs []btcjson.TxRawResult) {
	content, err := json.Marshal(btcjson.GetBlockVerboseTxResult{Hash: fmt.Sprintf("%064x", height), Height: int64(height), Tx: txs})
	require.NoError(t, err)
	compressed, err := types.GzipDeterministic(content, gzip.BestCompression)
	require.NoError(t, err)
	address, err := f.GetConsensusAddress()
	require.NoError(t, err)
	signature, err := f.privateKey.Sign(compressed)
	require.NoError(t, err)
	msg := &types.MsgBtcBlock{
		Height:       height,
		Hash:         fmt.Sprintf("%064x", height),
		BlockContent: compressed,
		Attestations: []*types.Attestation{{Address: address, Signature: signature}},
		Signer:       types.EBifrostSignerAddress,
	}
	_, err = keeper.NewMsgServerImpl(f.keeper).SetMsgReportBlock(f.ctx, msg)
	require.NoError(t, err)
	lastProcessed, err := f.keeper.GetLastProcessedBlock(f.ctx)
	require.NoError(t, err)
	require.Equal(t, height, lastProcessed, "block was not processed")
}

// A claimed UTXO spent together with a small unclaimed one gives a partially entitled output.
// Spending that output again must not reset its entitlement to its full value.
func TestSetMsgReportBlock_PartialEntitlementIsNotReset(t *testing.T) {
	const (
		claimedTxid = "1111111111111111111111111111111111111111111111111111111111111111"
		dustTxid    = "2222222222222222222222222222222222222222222222222222222222222222"
		txA         = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
		txB         = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
		claimedSats = 10 * btcutil.SatoshiPerBitcoin
		dustSats    = 10_000
		fee         = 2_000
	)
	// tx A spends the claimed UTXO plus the dust; its output is entitled to the dust minus the fee
	tx1 := btcjson.TxRawResult{
		Txid: txA,
		Vin:  []btcjson.Vin{{Txid: claimedTxid, Vout: 0}, {Txid: dustTxid, Vout: 0}},
		Vout: []btcjson.Vout{testVout(0, claimedSats+dustSats-fee)},
	}
	// tx B spends that output alone
	tx2 := btcjson.TxRawResult{
		Txid: txB,
		Vin:  []btcjson.Vin{{Txid: txA, Vout: 0}},
		Vout: []btcjson.Vout{testVout(0, claimedSats+dustSats-2*fee)},
	}

	for _, sameBlock := range []bool{true, false} {
		t.Run(fmt.Sprintf("same block %v", sameBlock), func(st *testing.T) {
			f := initFixture(st)
			setTestUtxo(st, f, claimedTxid, 0, claimedSats, 0)
			setTestUtxo(st, f, dustTxid, 0, dustSats, dustSats)

			if sameBlock {
				submitTestBlock(st, f, 800000, []btcjson.TxRawResult{tx1, tx2})
			} else {
				submitTestBlock(st, f, 800000, []btcjson.TxRawResult{tx1})
				require.Equal(st, uint64(dustSats-fee), getTestEntitlement(st, f, txA, 0))
				submitTestBlock(st, f, 800001, []btcjson.TxRawResult{tx2})
			}
			require.Equal(st, uint64(dustSats-2*fee), getTestEntitlement(st, f, txB, 0))
		})
	}
}

// The same loop, but tx B is a memo claim, which mints in the block that contains it.
func TestSetMsgReportBlock_PartialEntitlementMemoClaim(t *testing.T) {
	const (
		claimedTxid = "1111111111111111111111111111111111111111111111111111111111111111"
		dustTxid    = "2222222222222222222222222222222222222222222222222222222222222222"
		txA         = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
		txB         = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
		claimedSats = 10 * btcutil.SatoshiPerBitcoin
		dustSats    = 10_000
		fee         = 2_000
	)
	f := initFixture(t)
	minted := sdkmath.ZeroInt()
	f.bankKeeper.EXPECT().MintCoins(gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(
		func(_ context.Context, _ string, coins sdk.Coins) error {
			minted = minted.Add(coins.AmountOf(sdk.DefaultBondDenom))
			return nil
		}).AnyTimes()
	f.bankKeeper.EXPECT().SendCoinsFromModuleToAccount(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(nil).AnyTimes()
	setTestUtxo(t, f, claimedTxid, 0, claimedSats, 0)
	setTestUtxo(t, f, dustTxid, 0, dustSats, dustSats)
	memoAddr, err := f.GetRandomQbtcAddress()
	require.NoError(t, err)

	submitTestBlock(t, f, 800000, []btcjson.TxRawResult{
		{
			Txid: txA,
			Vin:  []btcjson.Vin{{Txid: claimedTxid, Vout: 0}, {Txid: dustTxid, Vout: 0}},
			Vout: []btcjson.Vout{testVout(0, claimedSats+dustSats-fee)},
		},
		{
			Txid: txB,
			Vin:  []btcjson.Vin{{Txid: txA, Vout: 0}},
			Vout: []btcjson.Vout{testVout(0, claimedSats+dustSats-2*fee), testClaimMemoVout(1, memoAddr)},
		},
	})
	require.Equal(t, sdkmath.NewInt(dustSats-2*fee).String(), minted.String())
	require.Equal(t, uint64(0), getTestEntitlement(t, f, txB, 0))
}

// claimable * amount does not fit in uint64 here (5e9 * 5e9 = 2.5e19).
func TestSetMsgReportBlock_EntitlementDoesNotOverflow(t *testing.T) {
	const (
		claimedTxid = "1111111111111111111111111111111111111111111111111111111111111111"
		openTxid    = "2222222222222222222222222222222222222222222222222222222222222222"
		txA         = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
		fiftyBTC    = 50 * btcutil.SatoshiPerBitcoin
	)
	f := initFixture(t)
	setTestUtxo(t, f, claimedTxid, 0, fiftyBTC, 0)
	setTestUtxo(t, f, openTxid, 0, fiftyBTC, fiftyBTC)

	submitTestBlock(t, f, 800000, []btcjson.TxRawResult{{
		Txid: txA,
		Vin:  []btcjson.Vin{{Txid: claimedTxid, Vout: 0}, {Txid: openTxid, Vout: 0}},
		Vout: []btcjson.Vout{testVout(0, fiftyBTC), testVout(1, fiftyBTC)},
	}})
	require.Equal(t, uint64(fiftyBTC/2), getTestEntitlement(t, f, txA, 0))
	require.Equal(t, uint64(fiftyBTC/2), getTestEntitlement(t, f, txA, 1))
}

// When every input is fully entitled, each output keeps its full value.
func TestSetMsgReportBlock_UnclaimedInputsKeepFullEntitlement(t *testing.T) {
	const (
		inTxid = "1111111111111111111111111111111111111111111111111111111111111111"
		txA    = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	)
	f := initFixture(t)
	setTestUtxo(t, f, inTxid, 0, 100_000_003, 100_000_003)
	setTestUtxo(t, f, inTxid, 1, 7, 7)

	submitTestBlock(t, f, 800000, []btcjson.TxRawResult{{
		Txid: txA,
		Vin:  []btcjson.Vin{{Txid: inTxid, Vout: 0}, {Txid: inTxid, Vout: 1}},
		Vout: []btcjson.Vout{testVout(0, 33_333_333), testVout(1, 66_666_667), testVout(2, 1)},
	}})
	require.Equal(t, uint64(33_333_333), getTestEntitlement(t, f, txA, 0))
	require.Equal(t, uint64(66_666_667), getTestEntitlement(t, f, txA, 1))
	require.Equal(t, uint64(1), getTestEntitlement(t, f, txA, 2))
}

// An input that is not in the store contributes nothing to the claimable or
// input totals. The outputs share the known claimable total pro rata, so they
// never get more than the known inputs had.
func TestSetMsgReportBlock_MissingInput(t *testing.T) {
	const (
		missingTxid = "1111111111111111111111111111111111111111111111111111111111111111"
		knownTxid   = "2222222222222222222222222222222222222222222222222222222222222222"
		txA         = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	)
	cases := []struct {
		name       string
		outputs    []int64
		entitlement []uint64
	}{
		// known input 100,000 < outputs 150,000: no fee can be computed, so the
		// full known 100,000 is split pro rata
		{"outputs above known inputs", []int64{90_000, 60_000}, []uint64{60_000, 40_000}},
		// known input 100,000 > outputs 80,000: the 20,000 fee comes off the
		// claimable total, and each output gets its full value
		{"outputs below known inputs", []int64{50_000, 30_000}, []uint64{50_000, 30_000}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(st *testing.T) {
			f := initFixture(st)
			setTestUtxo(st, f, knownTxid, 0, 100_000, 100_000)
			vouts := make([]btcjson.Vout, len(tc.outputs))
			for i, sats := range tc.outputs {
				vouts[i] = testVout(uint32(i), sats)
			}
			submitTestBlock(st, f, 800000, []btcjson.TxRawResult{{
				Txid: txA,
				Vin:  []btcjson.Vin{{Txid: missingTxid, Vout: 0}, {Txid: knownTxid, Vout: 0}},
				Vout: vouts,
			}})
			for i, want := range tc.entitlement {
				require.Equal(st, want, getTestEntitlement(st, f, txA, uint32(i)))
			}
		})
	}
}

// A UTXO record that cannot be read (here: bytes that do not decode) fails the
// block instead of being skipped as if the input did not exist.
func TestSetMsgReportBlock_UnreadableInputFailsBlock(t *testing.T) {
	const (
		badTxid = "3333333333333333333333333333333333333333333333333333333333333333"
		txA     = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	)
	f := initFixture(t)
	badKey := fmt.Sprintf("%s-0", badTxid)
	rawKey, err := collections.EncodeKeyWithPrefix(types.UTXOKeys.Bytes(), collections.StringKey, badKey)
	require.NoError(t, err)
	sdk.UnwrapSDKContext(f.ctx).KVStore(f.storeKey).Set(rawKey, []byte{0xff, 0xff, 0xff})
	_, err = f.keeper.Utxoes.Get(f.ctx, badKey)
	require.Error(t, err)
	require.NotErrorIs(t, err, collections.ErrNotFound)

	content, err := json.Marshal(btcjson.GetBlockVerboseTxResult{Hash: fmt.Sprintf("%064x", 800000), Height: 800000, Tx: []btcjson.TxRawResult{{
		Txid: txA,
		Vin:  []btcjson.Vin{{Txid: badTxid, Vout: 0}},
		Vout: []btcjson.Vout{testVout(0, 90_000)},
	}}})
	require.NoError(t, err)
	compressed, err := types.GzipDeterministic(content, gzip.BestCompression)
	require.NoError(t, err)
	address, err := f.GetConsensusAddress()
	require.NoError(t, err)
	signature, err := f.privateKey.Sign(compressed)
	require.NoError(t, err)
	_, err = keeper.NewMsgServerImpl(f.keeper).SetMsgReportBlock(f.ctx, &types.MsgBtcBlock{
		Height:       800000,
		Hash:         fmt.Sprintf("%064x", 800000),
		BlockContent: compressed,
		Attestations: []*types.Attestation{{Address: address, Signature: signature}},
		Signer:       types.EBifrostSignerAddress,
	})
	require.ErrorContains(t, err, "fail to get UTXO")

	lastProcessed, err := f.keeper.GetLastProcessedBlock(f.ctx)
	require.NoError(t, err)
	require.Zero(t, lastProcessed, "the block must not be applied")
	_, err = f.keeper.Utxoes.Get(f.ctx, fmt.Sprintf("%s-0", txA))
	require.ErrorIs(t, err, collections.ErrNotFound)
}
