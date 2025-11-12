package keeper_test

import (
	"compress/gzip"
	"os"
	"testing"

	"github.com/btcq-org/qbtc/x/qbtc/keeper"
	"github.com/btcq-org/qbtc/x/qbtc/types"
	"github.com/cometbft/cometbft/crypto/mldsa"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSetMsgReportBlock(t *testing.T) {
	f := initFixture(t)

	inputs := []struct {
		name      string
		fileName  string
		blockHash string
		height    uint64
		setup     func(st *testing.T)
		checkFunc func(st *testing.T)
	}{
		{
			name:      "block 0",
			height:    0,
			blockHash: "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f",
			fileName:  "../../../testdata/block/1.json",
			setup:     nil,
			checkFunc: func(st *testing.T) {
				// make sure coinbase UTXO is created
				key := "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b-0"
				utxo, err := f.keeper.Utxoes.Get(f.ctx, key)
				require.NoError(st, err)
				require.NotNil(st, utxo)
				require.Equal(st, utxo.EntitledAmount, uint64(5000000000))
			},
		},
		{
			name:      "block 300003",
			height:    300003,
			blockHash: "000000000000000082aee4ff546c1db5e1aa5f9bfbaa0c76300a792b3e91fce7",
			fileName:  "../../../testdata/block/300003.json",
			setup:     nil,
			checkFunc: func(st *testing.T) {
				// since we didn't preload utxos , so all the utxo is spent , which means
				coinbaseKey := "effbacb359a68252c25d349cea55eaff68ef549aef6aef0faa30e38ab48080a3-0"
				utxo, err := f.keeper.Utxoes.Get(f.ctx, coinbaseKey)
				require.NoError(st, err)
				require.NotNil(st, utxo)
				require.Equal(st, utxo.EntitledAmount, uint64(2502766489))

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
			setup: func(st *testing.T) {
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
			checkFunc: func(st *testing.T) {
				// since we didn't preload utxos , so all the utxo is spent , which means
				coinbaseKey := "effbacb359a68252c25d349cea55eaff68ef549aef6aef0faa30e38ab48080a3-0"
				utxo, err := f.keeper.Utxoes.Get(f.ctx, coinbaseKey)
				require.NoError(st, err)
				require.NotNil(st, utxo)
				require.Equal(st, utxo.EntitledAmount, uint64(2502766489))

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
			setup: func(st *testing.T) {
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
					Txid:           "d510799f177184922edfb98adcc023b1f13d087c2bad700798972f0defcffdca",
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
					Txid:           "d510799f177184922edfb98adcc023b1f13d087c2bad700798972f0defcffdca",
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
			checkFunc: func(st *testing.T) {
				// since we didn't preload utxos , so all the utxo is spent , which means
				coinbaseKey := "effbacb359a68252c25d349cea55eaff68ef549aef6aef0faa30e38ab48080a3-0"
				utxo, err := f.keeper.Utxoes.Get(f.ctx, coinbaseKey)
				require.NoError(st, err)
				require.NotNil(st, utxo)
				require.Equal(st, utxo.EntitledAmount, uint64(2502766489))

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
			fileContent, err := os.ReadFile(tc.fileName)
			assert.Nil(st, err)
			compressedContent, err := types.GzipDeterministic(fileContent, gzip.BestCompression)
			assert.Nil(st, err, "failed to compress block data")
			privateKey := mldsa.GenPrivKey()
			address, err := f.GetAddressFromPubKey(privateKey.PubKey().Address())
			assert.Nil(st, err)
			signature, err := privateKey.Sign(compressedContent)
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
				Signer: address,
			}
			if tc.setup != nil {
				tc.setup(st)
			}
			server := keeper.NewMsgServerImpl(f.keeper)
			_, err = server.SetMsgReportBlock(f.ctx, msg)
			assert.NoError(st, err)
			tc.checkFunc(st)
		})
	}

}
