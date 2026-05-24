package keeper_test

import (
	"testing"

	"github.com/btcq-org/qbtc/x/qbtc/keeper"
	"github.com/btcq-org/qbtc/x/qbtc/types"
	sdk "github.com/cosmos/cosmos-sdk/types"
	govtypes "github.com/cosmos/cosmos-sdk/x/gov/types"
	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHandleMsgGovClaimUTXO(t *testing.T) {
	tests := []struct {
		name      string
		setup     func(t *testing.T, f *fixture)
		msg       *types.MsgGovClaimUTXO
		expectErr bool
		checkFunc func(t *testing.T, f *fixture)
	}{
		{
			name: "successfully claim multiple UTXOs - no fund addresses set (100% reserve)",
			setup: func(t *testing.T, f *fixture) {
				utxo1 := types.UTXO{
					Txid: "txid1", Vout: 0, Amount: 100000000, EntitledAmount: 50000000,
					ScriptPubKey: &types.ScriptPubKeyResult{Hex: "76a91488ac", Type: "pubkeyhash", Address: "1J6QsrCXRTZusGEeyg44BcoqgM4SZXTXhC"},
				}
				utxo2 := types.UTXO{
					Txid: "txid2", Vout: 1, Amount: 200000000, EntitledAmount: 150000000,
					ScriptPubKey: &types.ScriptPubKeyResult{Hex: "76a91488ac", Type: "pubkeyhash", Address: "1J6QsrCXRTZusGEeyg44BcoqgM4SZXTXhC"},
				}
				utxo3 := types.UTXO{
					Txid: "txid3", Vout: 2, Amount: 300000000, EntitledAmount: 250000000,
					ScriptPubKey: &types.ScriptPubKeyResult{Hex: "76a91488ac", Type: "pubkeyhash", Address: "1J6QsrCXRTZusGEeyg44BcoqgM4SZXTXhC"},
				}
				require.NoError(t, f.keeper.Utxoes.Set(f.ctx, "txid1-0", utxo1))
				require.NoError(t, f.keeper.Utxoes.Set(f.ctx, "txid2-1", utxo2))
				require.NoError(t, f.keeper.Utxoes.Set(f.ctx, "txid3-2", utxo3))

				// No fund addresses → full amount minted to qbtc, sent to reserve.
				f.bankKeeper.EXPECT().
					MintCoins(gomock.Any(), types.ModuleName, sdk.NewCoins(sdk.NewInt64Coin(sdk.DefaultBondDenom, 50000000))).
					Return(nil)
				f.bankKeeper.EXPECT().
					SendCoinsFromModuleToModule(gomock.Any(), types.ModuleName, types.ReserveModuleName, sdk.NewCoins(sdk.NewInt64Coin(sdk.DefaultBondDenom, 50000000))).
					Return(nil)
				f.bankKeeper.EXPECT().
					MintCoins(gomock.Any(), types.ModuleName, sdk.NewCoins(sdk.NewInt64Coin(sdk.DefaultBondDenom, 150000000))).
					Return(nil)
				f.bankKeeper.EXPECT().
					SendCoinsFromModuleToModule(gomock.Any(), types.ModuleName, types.ReserveModuleName, sdk.NewCoins(sdk.NewInt64Coin(sdk.DefaultBondDenom, 150000000))).
					Return(nil)
				f.bankKeeper.EXPECT().
					MintCoins(gomock.Any(), types.ModuleName, sdk.NewCoins(sdk.NewInt64Coin(sdk.DefaultBondDenom, 250000000))).
					Return(nil)
				f.bankKeeper.EXPECT().
					SendCoinsFromModuleToModule(gomock.Any(), types.ModuleName, types.ReserveModuleName, sdk.NewCoins(sdk.NewInt64Coin(sdk.DefaultBondDenom, 250000000))).
					Return(nil)
			},
			msg: &types.MsgGovClaimUTXO{
				Authority: govtypes.ModuleName,
				Utxos:     []*types.ClaimUTXO{{Txid: "txid1", Vout: 0}, {Txid: "txid2", Vout: 1}, {Txid: "txid3", Vout: 2}},
			},
			expectErr: false,
			checkFunc: func(t *testing.T, f *fixture) {
				utxo1, err := f.keeper.Utxoes.Get(f.ctx, "txid1-0")
				require.NoError(t, err)
				assert.Equal(t, uint64(0), utxo1.EntitledAmount)
				assert.Equal(t, uint64(100000000), utxo1.Amount)

				utxo2, err := f.keeper.Utxoes.Get(f.ctx, "txid2-1")
				require.NoError(t, err)
				assert.Equal(t, uint64(0), utxo2.EntitledAmount)

				utxo3, err := f.keeper.Utxoes.Get(f.ctx, "txid3-2")
				require.NoError(t, err)
				assert.Equal(t, uint64(0), utxo3.EntitledAmount)
			},
		},
		{
			name: "split - only DevFundAddress set (5% dev, 95% reserve)",
			setup: func(t *testing.T, f *fixture) {
				devAddrRaw := make([]byte, 20)
				copy(devAddrRaw, []byte("dev_fund_address_000"))
				devAddrStr, err := f.addressCodec.BytesToString(devAddrRaw)
				require.NoError(t, err)
				devAddr := sdk.AccAddress(devAddrRaw)

				require.NoError(t, f.keeper.StringParams.Set(f.ctx, types.DevFundAddressKey, devAddrStr))

				utxo := types.UTXO{
					Txid: "txid1", Vout: 0, Amount: 100000000, EntitledAmount: 100000000,
					ScriptPubKey: &types.ScriptPubKeyResult{Hex: "76a91488ac", Type: "pubkeyhash", Address: "1J6QsrCXRTZusGEeyg44BcoqgM4SZXTXhC"},
				}
				require.NoError(t, f.keeper.Utxoes.Set(f.ctx, "txid1-0", utxo))

				// 5% of 100000000 = 5000000 to dev, 95000000 to reserve.
				f.bankKeeper.EXPECT().
					MintCoins(gomock.Any(), types.ModuleName, sdk.NewCoins(sdk.NewInt64Coin(sdk.DefaultBondDenom, 100000000))).
					Return(nil)
				f.bankKeeper.EXPECT().
					SendCoinsFromModuleToAccount(gomock.Any(), types.ModuleName, devAddr, sdk.NewCoins(sdk.NewInt64Coin(sdk.DefaultBondDenom, 5000000))).
					Return(nil)
				f.bankKeeper.EXPECT().
					SendCoinsFromModuleToModule(gomock.Any(), types.ModuleName, types.ReserveModuleName, sdk.NewCoins(sdk.NewInt64Coin(sdk.DefaultBondDenom, 95000000))).
					Return(nil)
			},
			msg: &types.MsgGovClaimUTXO{
				Authority: govtypes.ModuleName,
				Utxos:     []*types.ClaimUTXO{{Txid: "txid1", Vout: 0}},
			},
			expectErr: false,
			checkFunc: func(t *testing.T, f *fixture) {
				utxo, err := f.keeper.Utxoes.Get(f.ctx, "txid1-0")
				require.NoError(t, err)
				assert.Equal(t, uint64(0), utxo.EntitledAmount)
			},
		},
		{
			name: "split - only MarketingFundAddress set (5% mkt, 95% reserve)",
			setup: func(t *testing.T, f *fixture) {
				mktAddrRaw := make([]byte, 20)
				copy(mktAddrRaw, []byte("mkt_fund_address_000"))
				mktAddrStr, err := f.addressCodec.BytesToString(mktAddrRaw)
				require.NoError(t, err)
				mktAddr := sdk.AccAddress(mktAddrRaw)

				require.NoError(t, f.keeper.StringParams.Set(f.ctx, types.MarketingFundAddressKey, mktAddrStr))

				utxo := types.UTXO{
					Txid: "txid1", Vout: 0, Amount: 100000000, EntitledAmount: 100000000,
					ScriptPubKey: &types.ScriptPubKeyResult{Hex: "76a91488ac", Type: "pubkeyhash", Address: "1J6QsrCXRTZusGEeyg44BcoqgM4SZXTXhC"},
				}
				require.NoError(t, f.keeper.Utxoes.Set(f.ctx, "txid1-0", utxo))

				f.bankKeeper.EXPECT().
					MintCoins(gomock.Any(), types.ModuleName, sdk.NewCoins(sdk.NewInt64Coin(sdk.DefaultBondDenom, 100000000))).
					Return(nil)
				f.bankKeeper.EXPECT().
					SendCoinsFromModuleToAccount(gomock.Any(), types.ModuleName, mktAddr, sdk.NewCoins(sdk.NewInt64Coin(sdk.DefaultBondDenom, 5000000))).
					Return(nil)
				f.bankKeeper.EXPECT().
					SendCoinsFromModuleToModule(gomock.Any(), types.ModuleName, types.ReserveModuleName, sdk.NewCoins(sdk.NewInt64Coin(sdk.DefaultBondDenom, 95000000))).
					Return(nil)
			},
			msg: &types.MsgGovClaimUTXO{
				Authority: govtypes.ModuleName,
				Utxos:     []*types.ClaimUTXO{{Txid: "txid1", Vout: 0}},
			},
			expectErr: false,
			checkFunc: func(t *testing.T, f *fixture) {
				utxo, err := f.keeper.Utxoes.Get(f.ctx, "txid1-0")
				require.NoError(t, err)
				assert.Equal(t, uint64(0), utxo.EntitledAmount)
			},
		},
		{
			name: "split - both fund addresses set (5% dev, 5% mkt, 90% reserve)",
			setup: func(t *testing.T, f *fixture) {
				devAddrRaw := make([]byte, 20)
				copy(devAddrRaw, []byte("dev_fund_address_000"))
				devAddrStr, err := f.addressCodec.BytesToString(devAddrRaw)
				require.NoError(t, err)
				devAddr := sdk.AccAddress(devAddrRaw)

				mktAddrRaw := make([]byte, 20)
				copy(mktAddrRaw, []byte("mkt_fund_address_000"))
				mktAddrStr, err := f.addressCodec.BytesToString(mktAddrRaw)
				require.NoError(t, err)
				mktAddr := sdk.AccAddress(mktAddrRaw)

				require.NoError(t, f.keeper.StringParams.Set(f.ctx, types.DevFundAddressKey, devAddrStr))
				require.NoError(t, f.keeper.StringParams.Set(f.ctx, types.MarketingFundAddressKey, mktAddrStr))

				utxo := types.UTXO{
					Txid: "txid1", Vout: 0, Amount: 100000000, EntitledAmount: 100000000,
					ScriptPubKey: &types.ScriptPubKeyResult{Hex: "76a91488ac", Type: "pubkeyhash", Address: "1J6QsrCXRTZusGEeyg44BcoqgM4SZXTXhC"},
				}
				require.NoError(t, f.keeper.Utxoes.Set(f.ctx, "txid1-0", utxo))

				// 5% of 100000000 = 5000000 to dev, 5000000 to mkt, 90000000 to reserve.
				f.bankKeeper.EXPECT().
					MintCoins(gomock.Any(), types.ModuleName, sdk.NewCoins(sdk.NewInt64Coin(sdk.DefaultBondDenom, 100000000))).
					Return(nil)
				f.bankKeeper.EXPECT().
					SendCoinsFromModuleToAccount(gomock.Any(), types.ModuleName, devAddr, sdk.NewCoins(sdk.NewInt64Coin(sdk.DefaultBondDenom, 5000000))).
					Return(nil)
				f.bankKeeper.EXPECT().
					SendCoinsFromModuleToAccount(gomock.Any(), types.ModuleName, mktAddr, sdk.NewCoins(sdk.NewInt64Coin(sdk.DefaultBondDenom, 5000000))).
					Return(nil)
				f.bankKeeper.EXPECT().
					SendCoinsFromModuleToModule(gomock.Any(), types.ModuleName, types.ReserveModuleName, sdk.NewCoins(sdk.NewInt64Coin(sdk.DefaultBondDenom, 90000000))).
					Return(nil)
			},
			msg: &types.MsgGovClaimUTXO{
				Authority: govtypes.ModuleName,
				Utxos:     []*types.ClaimUTXO{{Txid: "txid1", Vout: 0}},
			},
			expectErr: false,
			checkFunc: func(t *testing.T, f *fixture) {
				utxo, err := f.keeper.Utxoes.Get(f.ctx, "txid1-0")
				require.NoError(t, err)
				assert.Equal(t, uint64(0), utxo.EntitledAmount)
			},
		},
		{
			name: "unauthorized authority",
			setup: func(t *testing.T, f *fixture) {},
			msg: &types.MsgGovClaimUTXO{
				Authority: "wrong-authority",
				Utxos:     []*types.ClaimUTXO{{Txid: "txid1", Vout: 0}},
			},
			expectErr: true,
		},
		{
			name:  "invalid message - no authority",
			setup: func(t *testing.T, f *fixture) {},
			msg: &types.MsgGovClaimUTXO{
				Authority: "",
				Utxos:     []*types.ClaimUTXO{{Txid: "txid1", Vout: 0}},
			},
			expectErr: true,
		},
		{
			name:  "invalid message - no UTXOs",
			setup: func(t *testing.T, f *fixture) {},
			msg: &types.MsgGovClaimUTXO{
				Authority: govtypes.ModuleName,
				Utxos:     []*types.ClaimUTXO{},
			},
			expectErr: true,
		},
		{
			name:  "invalid message - missing txid",
			setup: func(t *testing.T, f *fixture) {},
			msg: &types.MsgGovClaimUTXO{
				Authority: govtypes.ModuleName,
				Utxos:     []*types.ClaimUTXO{{Txid: "", Vout: 0}},
			},
			expectErr: true,
		},
		{
			name:  "UTXO not found",
			setup: func(t *testing.T, f *fixture) {},
			msg: &types.MsgGovClaimUTXO{
				Authority: govtypes.ModuleName,
				Utxos:     []*types.ClaimUTXO{{Txid: "nonexistent", Vout: 0}},
			},
			expectErr: true,
		},
		{
			name: "UTXO with zero entitled amount",
			setup: func(t *testing.T, f *fixture) {
				utxo := types.UTXO{
					Txid: "txid4", Vout: 0, Amount: 100000000, EntitledAmount: 0,
					ScriptPubKey: &types.ScriptPubKeyResult{Hex: "76a91488ac", Type: "pubkeyhash", Address: "1J6QsrCXRTZusGEeyg44BcoqgM4SZXTXhC"},
				}
				require.NoError(t, f.keeper.Utxoes.Set(f.ctx, "txid4-0", utxo))
				// MintCoins should not be called for zero entitled amount.
			},
			msg: &types.MsgGovClaimUTXO{
				Authority: govtypes.ModuleName,
				Utxos:     []*types.ClaimUTXO{{Txid: "txid4", Vout: 0}},
			},
			expectErr: false,
			checkFunc: func(t *testing.T, f *fixture) {
				utxo, err := f.keeper.Utxoes.Get(f.ctx, "txid4-0")
				require.NoError(t, err)
				assert.Equal(t, uint64(0), utxo.EntitledAmount)
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := initFixture(t)

			if tc.setup != nil {
				tc.setup(t, f)
			}

			server := keeper.NewMsgServerImpl(f.keeper)
			resp, err := server.GovClaimUTXO(f.ctx, tc.msg)

			if tc.expectErr {
				assert.Error(t, err)
				assert.Nil(t, resp)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, resp)
				if tc.checkFunc != nil {
					tc.checkFunc(t, f)
				}
			}
		})
	}
}
