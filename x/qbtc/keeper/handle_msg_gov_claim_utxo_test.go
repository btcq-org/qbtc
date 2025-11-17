package keeper_test

import (
	"testing"

	"cosmossdk.io/math"
	storetypes "cosmossdk.io/store/types"
	"github.com/btcq-org/qbtc/common"
	"github.com/btcq-org/qbtc/x/qbtc/keeper"
	module "github.com/btcq-org/qbtc/x/qbtc/module"
	qbtctestutil "github.com/btcq-org/qbtc/x/qbtc/testutil"
	"github.com/btcq-org/qbtc/x/qbtc/types"
	"github.com/cometbft/cometbft/crypto/mldsa"
	addresscodec "github.com/cosmos/cosmos-sdk/codec/address"
	"github.com/cosmos/cosmos-sdk/crypto/codec"
	"github.com/cosmos/cosmos-sdk/runtime"
	"github.com/cosmos/cosmos-sdk/testutil"
	sdk "github.com/cosmos/cosmos-sdk/types"
	moduletestutil "github.com/cosmos/cosmos-sdk/types/module/testutil"
	govtypes "github.com/cosmos/cosmos-sdk/x/gov/types"
	stakingtypes "github.com/cosmos/cosmos-sdk/x/staking/types"
	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHandleMsgGovClaimUTXO(t *testing.T) {
	tests := []struct {
		name      string
		setup     func(t *testing.T, f *fixture, bankKeeper *qbtctestutil.MockBankKeeper)
		msg       *types.MsgGovClaimUTXO
		expectErr bool
		checkFunc func(t *testing.T, f *fixture)
	}{
		{
			name: "successfully claim multiple UTXOs",
			setup: func(t *testing.T, f *fixture, bankKeeper *qbtctestutil.MockBankKeeper) {
				// Set up three UTXOs with different entitled amounts
				utxo1 := types.UTXO{
					Txid:           "txid1",
					Vout:           0,
					Amount:         100000000,
					EntitledAmount: 50000000,
					ScriptPubKey: &types.ScriptPubKeyResult{
						Hex:     "76a91488ac",
						Type:    "pubkeyhash",
						Address: "1J6QsrCXRTZusGEeyg44BcoqgM4SZXTXhC",
					},
				}
				utxo2 := types.UTXO{
					Txid:           "txid2",
					Vout:           1,
					Amount:         200000000,
					EntitledAmount: 150000000,
					ScriptPubKey: &types.ScriptPubKeyResult{
						Hex:     "76a91488ac",
						Type:    "pubkeyhash",
						Address: "1J6QsrCXRTZusGEeyg44BcoqgM4SZXTXhC",
					},
				}
				utxo3 := types.UTXO{
					Txid:           "txid3",
					Vout:           2,
					Amount:         300000000,
					EntitledAmount: 250000000,
					ScriptPubKey: &types.ScriptPubKeyResult{
						Hex:     "76a91488ac",
						Type:    "pubkeyhash",
						Address: "1J6QsrCXRTZusGEeyg44BcoqgM4SZXTXhC",
					},
				}

				key1 := "txid1-0"
				key2 := "txid2-1"
				key3 := "txid3-2"

				require.NoError(t, f.keeper.Utxoes.Set(f.ctx, key1, utxo1))
				require.NoError(t, f.keeper.Utxoes.Set(f.ctx, key2, utxo2))
				require.NoError(t, f.keeper.Utxoes.Set(f.ctx, key3, utxo3))

				// Expect MintCoins to be called three times with the correct amounts
				bankKeeper.EXPECT().
					MintCoins(gomock.Any(), types.ReserveModuleName, sdk.NewCoins(sdk.NewInt64Coin(sdk.DefaultBondDenom, 50000000))).
					Return(nil)
				bankKeeper.EXPECT().
					MintCoins(gomock.Any(), types.ReserveModuleName, sdk.NewCoins(sdk.NewInt64Coin(sdk.DefaultBondDenom, 150000000))).
					Return(nil)
				bankKeeper.EXPECT().
					MintCoins(gomock.Any(), types.ReserveModuleName, sdk.NewCoins(sdk.NewInt64Coin(sdk.DefaultBondDenom, 250000000))).
					Return(nil)
			},
			msg: &types.MsgGovClaimUTXO{
				Authority: govtypes.ModuleName,
				Utxos: []*types.ClaimUTXO{
					{Txid: "txid1", Vout: 0},
					{Txid: "txid2", Vout: 1},
					{Txid: "txid3", Vout: 2},
				},
			},
			expectErr: false,
			checkFunc: func(t *testing.T, f *fixture) {
				// Verify all UTXOs have EntitledAmount set to 0
				utxo1, err := f.keeper.Utxoes.Get(f.ctx, "txid1-0")
				require.NoError(t, err)
				assert.Equal(t, uint64(0), utxo1.EntitledAmount)
				assert.Equal(t, uint64(100000000), utxo1.Amount) // Original amount should remain

				utxo2, err := f.keeper.Utxoes.Get(f.ctx, "txid2-1")
				require.NoError(t, err)
				assert.Equal(t, uint64(0), utxo2.EntitledAmount)
				assert.Equal(t, uint64(200000000), utxo2.Amount)

				utxo3, err := f.keeper.Utxoes.Get(f.ctx, "txid3-2")
				require.NoError(t, err)
				assert.Equal(t, uint64(0), utxo3.EntitledAmount)
				assert.Equal(t, uint64(300000000), utxo3.Amount)
			},
		},
		{
			name: "unauthorized authority",
			setup: func(t *testing.T, f *fixture, bankKeeper *qbtctestutil.MockBankKeeper) {
				// No setup needed, just testing authorization
			},
			msg: &types.MsgGovClaimUTXO{
				Authority: "wrong-authority",
				Utxos: []*types.ClaimUTXO{
					{Txid: "txid1", Vout: 0},
				},
			},
			expectErr: true,
			checkFunc: nil,
		},
		{
			name: "invalid message - no authority",
			setup: func(t *testing.T, f *fixture, bankKeeper *qbtctestutil.MockBankKeeper) {
				// No setup needed
			},
			msg: &types.MsgGovClaimUTXO{
				Authority: "",
				Utxos: []*types.ClaimUTXO{
					{Txid: "txid1", Vout: 0},
				},
			},
			expectErr: true,
			checkFunc: nil,
		},
		{
			name: "invalid message - no UTXOs",
			setup: func(t *testing.T, f *fixture, bankKeeper *qbtctestutil.MockBankKeeper) {
				// No setup needed
			},
			msg: &types.MsgGovClaimUTXO{
				Authority: govtypes.ModuleName,
				Utxos:     []*types.ClaimUTXO{},
			},
			expectErr: true,
			checkFunc: nil,
		},
		{
			name: "invalid message - missing txid",
			setup: func(t *testing.T, f *fixture, bankKeeper *qbtctestutil.MockBankKeeper) {
				// No setup needed
			},
			msg: &types.MsgGovClaimUTXO{
				Authority: govtypes.ModuleName,
				Utxos: []*types.ClaimUTXO{
					{Txid: "", Vout: 0},
				},
			},
			expectErr: true,
			checkFunc: nil,
		},
		{
			name: "UTXO not found",
			setup: func(t *testing.T, f *fixture, bankKeeper *qbtctestutil.MockBankKeeper) {
				// Don't set up any UTXOs
			},
			msg: &types.MsgGovClaimUTXO{
				Authority: govtypes.ModuleName,
				Utxos: []*types.ClaimUTXO{
					{Txid: "nonexistent", Vout: 0},
				},
			},
			expectErr: true,
			checkFunc: nil,
		},
		{
			name: "UTXO with zero entitled amount",
			setup: func(t *testing.T, f *fixture, bankKeeper *qbtctestutil.MockBankKeeper) {
				// Set up a UTXO with zero entitled amount
				utxo := types.UTXO{
					Txid:           "txid4",
					Vout:           0,
					Amount:         100000000,
					EntitledAmount: 0, // Already claimed
					ScriptPubKey: &types.ScriptPubKeyResult{
						Hex:     "76a91488ac",
						Type:    "pubkeyhash",
						Address: "1J6QsrCXRTZusGEeyg44BcoqgM4SZXTXhC",
					},
				}
				require.NoError(t, f.keeper.Utxoes.Set(f.ctx, "txid4-0", utxo))
				// MintCoins should not be called for zero entitled amount
			},
			msg: &types.MsgGovClaimUTXO{
				Authority: govtypes.ModuleName,
				Utxos: []*types.ClaimUTXO{
					{Txid: "txid4", Vout: 0},
				},
			},
			expectErr: false,
			checkFunc: func(t *testing.T, f *fixture) {
				// UTXO should still have zero entitled amount
				utxo, err := f.keeper.Utxoes.Get(f.ctx, "txid4-0")
				require.NoError(t, err)
				assert.Equal(t, uint64(0), utxo.EntitledAmount)
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Create a new fixture with a controlled bankKeeper
			sdk.GetConfig().SetBech32PrefixForAccount(common.AccountAddressPrefix, common.AccountAddressPrefix+sdk.PrefixPublic)
			sdk.GetConfig().SetBech32PrefixForValidator(common.AccountAddressPrefix+sdk.PrefixValidator, common.AccountAddressPrefix+sdk.PrefixPublic)
			encCfg := moduletestutil.MakeTestEncodingConfig(module.AppModule{})
			addressCodec := addresscodec.NewBech32Codec(common.AccountAddressPrefix)
			validatorAddressCodec := addresscodec.NewBech32Codec(common.AccountAddressPrefix + sdk.PrefixValidator)
			storeKey := storetypes.NewKVStoreKey(types.StoreKey)

			storeService := runtime.NewKVStoreService(storeKey)
			ctx := testutil.DefaultContextWithDB(t, storeKey, storetypes.NewTransientStoreKey("transient_test")).Ctx
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			stakingKeeper := qbtctestutil.NewMockStakingKeeper(ctrl)
			privateKey := mldsa.GenPrivKey()
			pubKey := privateKey.PubKey()
			pKey, err := codec.FromCmtPubKeyInterface(pubKey)
			require.NoError(t, err)
			validator, err := stakingtypes.NewValidator("", pKey, stakingtypes.Description{})
			require.NoError(t, err)
			validator.Status = stakingtypes.Bonded
			validator.Tokens = math.NewInt(1000000000)

			stakingKeeper.EXPECT().GetLastTotalPower(gomock.Any()).AnyTimes().Return(math.NewInt(1000000), nil)
			stakingKeeper.EXPECT().GetValidator(gomock.Any(), gomock.Any()).AnyTimes().Return(validator, nil)
			stakingKeeper.EXPECT().PowerReduction(gomock.Any()).AnyTimes().Return(math.NewInt(1000))

			authKeeper := qbtctestutil.NewMockAuthKeeper(ctrl)

			bankKeeper := qbtctestutil.NewMockBankKeeper(ctrl)
			k := keeper.NewKeeper(
				storeService,
				encCfg.Codec,
				addressCodec,
				stakingKeeper,
				bankKeeper,
				authKeeper,
				govtypes.ModuleName,
			)

			f := &fixture{
				ctx:                   ctx,
				keeper:                k,
				addressCodec:          addressCodec,
				validator:             validator,
				privateKey:            privateKey,
				validatorAddressCodec: validatorAddressCodec,
			}

			if tc.setup != nil {
				tc.setup(t, f, bankKeeper)
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
