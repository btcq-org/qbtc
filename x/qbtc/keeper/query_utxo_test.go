package keeper_test

import (
	"testing"

	"github.com/btcq-org/qbtc/x/qbtc/keeper"
	"github.com/btcq-org/qbtc/x/qbtc/types"
	"github.com/cosmos/cosmos-sdk/types/query"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestQueryUTXOsByAddress(t *testing.T) {
	tests := []struct {
		name      string
		setup     func(t *testing.T, f *fixture)
		req       *types.QueryUTXOsByAddressRequest
		expectErr bool
		checkFunc func(t *testing.T, resp *types.QueryUTXOsByAddressResponse)
	}{
		{
			name: "returns UTXOs matching the requested address",
			setup: func(t *testing.T, f *fixture) {
				utxo1 := types.UTXO{
					Txid:           "aaa1000000000000000000000000000000000000000000000000000000000001",
					Vout:           0,
					Amount:         100000000,
					EntitledAmount: 50000000,
					ScriptPubKey: &types.ScriptPubKeyResult{
						Hex:     "76a91488ac",
						Type:    "pubkeyhash",
						Address: "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa",
					},
				}
				utxo2 := types.UTXO{
					Txid:           "aaa2000000000000000000000000000000000000000000000000000000000002",
					Vout:           1,
					Amount:         200000000,
					EntitledAmount: 0,
					ScriptPubKey: &types.ScriptPubKeyResult{
						Hex:     "76a91488ac",
						Type:    "pubkeyhash",
						Address: "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa",
					},
				}
				utxo3 := types.UTXO{
					Txid:           "bbb1000000000000000000000000000000000000000000000000000000000001",
					Vout:           0,
					Amount:         300000000,
					EntitledAmount: 150000000,
					ScriptPubKey: &types.ScriptPubKeyResult{
						Hex:     "76a91488ac",
						Type:    "pubkeyhash",
						Address: "3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy",
					},
				}
				require.NoError(t, f.keeper.Utxoes.Set(f.ctx, utxo1.GetKey(), utxo1))
				require.NoError(t, f.keeper.Utxoes.Set(f.ctx, utxo2.GetKey(), utxo2))
				require.NoError(t, f.keeper.Utxoes.Set(f.ctx, utxo3.GetKey(), utxo3))
			},
			req: &types.QueryUTXOsByAddressRequest{
				BtcAddress: "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa",
			},
			expectErr: false,
			checkFunc: func(t *testing.T, resp *types.QueryUTXOsByAddressResponse) {
				assert.Len(t, resp.Utxos, 2)
				assert.Equal(t, uint64(2), resp.Pagination.Total)
				for _, utxo := range resp.Utxos {
					assert.Equal(t, "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa", utxo.ScriptPubKey.Address)
				}
			},
		},
		{
			name:  "empty address returns error",
			setup: func(t *testing.T, f *fixture) {},
			req: &types.QueryUTXOsByAddressRequest{
				BtcAddress: "",
			},
			expectErr: true,
			checkFunc: nil,
		},
		{
			name:  "non-existent address returns empty result",
			setup: func(t *testing.T, f *fixture) {},
			req: &types.QueryUTXOsByAddressRequest{
				BtcAddress: "bc1qnonexistent",
			},
			expectErr: false,
			checkFunc: func(t *testing.T, resp *types.QueryUTXOsByAddressResponse) {
				assert.Empty(t, resp.Utxos)
				assert.Equal(t, uint64(0), resp.Pagination.Total)
			},
		},
		{
			name: "pagination with limit",
			setup: func(t *testing.T, f *fixture) {
				for i := range 5 {
					utxo := types.UTXO{
						Txid:           "ccc" + string(rune('1'+i)) + "000000000000000000000000000000000000000000000000000000000001",
						Vout:           uint32(i),
						Amount:         100000000,
						EntitledAmount: 50000000,
						ScriptPubKey: &types.ScriptPubKeyResult{
							Hex:     "76a91488ac",
							Type:    "pubkeyhash",
							Address: "1PaginatedAddr",
						},
					}
					require.NoError(t, f.keeper.Utxoes.Set(f.ctx, utxo.GetKey(), utxo))
				}
			},
			req: &types.QueryUTXOsByAddressRequest{
				BtcAddress: "1PaginatedAddr",
				Pagination: &query.PageRequest{Limit: 2},
			},
			expectErr: false,
			checkFunc: func(t *testing.T, resp *types.QueryUTXOsByAddressResponse) {
				assert.Len(t, resp.Utxos, 2)
				assert.Equal(t, uint64(5), resp.Pagination.Total)
			},
		},
		{
			name: "pagination with offset",
			setup: func(t *testing.T, f *fixture) {
				for i := range 5 {
					utxo := types.UTXO{
						Txid:           "ddd" + string(rune('1'+i)) + "000000000000000000000000000000000000000000000000000000000001",
						Vout:           uint32(i),
						Amount:         100000000,
						EntitledAmount: 50000000,
						ScriptPubKey: &types.ScriptPubKeyResult{
							Hex:     "76a91488ac",
							Type:    "pubkeyhash",
							Address: "1OffsetAddr",
						},
					}
					require.NoError(t, f.keeper.Utxoes.Set(f.ctx, utxo.GetKey(), utxo))
				}
			},
			req: &types.QueryUTXOsByAddressRequest{
				BtcAddress: "1OffsetAddr",
				Pagination: &query.PageRequest{Offset: 3, Limit: 10},
			},
			expectErr: false,
			checkFunc: func(t *testing.T, resp *types.QueryUTXOsByAddressResponse) {
				assert.Len(t, resp.Utxos, 2)
				assert.Equal(t, uint64(5), resp.Pagination.Total)
			},
		},
		{
			name: "pagination offset beyond total returns empty",
			setup: func(t *testing.T, f *fixture) {
				utxo := types.UTXO{
					Txid:           "eee1000000000000000000000000000000000000000000000000000000000001",
					Vout:           0,
					Amount:         100000000,
					EntitledAmount: 50000000,
					ScriptPubKey: &types.ScriptPubKeyResult{
						Hex:     "76a91488ac",
						Type:    "pubkeyhash",
						Address: "1BeyondAddr",
					},
				}
				require.NoError(t, f.keeper.Utxoes.Set(f.ctx, utxo.GetKey(), utxo))
			},
			req: &types.QueryUTXOsByAddressRequest{
				BtcAddress: "1BeyondAddr",
				Pagination: &query.PageRequest{Offset: 100, Limit: 10},
			},
			expectErr: false,
			checkFunc: func(t *testing.T, resp *types.QueryUTXOsByAddressResponse) {
				assert.Empty(t, resp.Utxos)
				assert.Equal(t, uint64(1), resp.Pagination.Total)
			},
		},
		{
			name: "reflects entitled_amount changes after claim",
			setup: func(t *testing.T, f *fixture) {
				utxo := types.UTXO{
					Txid:           "fff1000000000000000000000000000000000000000000000000000000000001",
					Vout:           0,
					Amount:         100000000,
					EntitledAmount: 50000000,
					ScriptPubKey: &types.ScriptPubKeyResult{
						Hex:     "76a91488ac",
						Type:    "pubkeyhash",
						Address: "1ClaimedAddr",
					},
				}
				require.NoError(t, f.keeper.Utxoes.Set(f.ctx, utxo.GetKey(), utxo))

				// Simulate claiming: update entitled_amount to 0
				utxo.EntitledAmount = 0
				require.NoError(t, f.keeper.Utxoes.Set(f.ctx, utxo.GetKey(), utxo))
			},
			req: &types.QueryUTXOsByAddressRequest{
				BtcAddress: "1ClaimedAddr",
			},
			expectErr: false,
			checkFunc: func(t *testing.T, resp *types.QueryUTXOsByAddressResponse) {
				assert.Len(t, resp.Utxos, 1)
				assert.Equal(t, uint64(0), resp.Utxos[0].EntitledAmount)
				assert.Equal(t, uint64(100000000), resp.Utxos[0].Amount)
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := initFixture(t)
			queryClient := keeper.NewQueryServerImpl(f.keeper)

			if tc.setup != nil {
				tc.setup(t, f)
			}

			resp, err := queryClient.UTXOsByAddress(f.ctx, tc.req)

			if tc.expectErr {
				assert.Error(t, err)
				assert.Nil(t, resp)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, resp)
				if tc.checkFunc != nil {
					tc.checkFunc(t, resp)
				}
			}
		})
	}
}
