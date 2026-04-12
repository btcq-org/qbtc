package keeper_test

import (
	"errors"
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
	sdkerrors "github.com/cosmos/cosmos-sdk/types/errors"
	moduletestutil "github.com/cosmos/cosmos-sdk/types/module/testutil"
	govtypes "github.com/cosmos/cosmos-sdk/x/gov/types"
	stakingtypes "github.com/cosmos/cosmos-sdk/x/staking/types"
	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSetNodePeerAddress(t *testing.T) {
	validSigner := qbtctestutil.GetRandomQBTCAddress()

	tests := []struct {
		name                    string
		setup                   func(t *testing.T, f *fixture, stakingKeeper *qbtctestutil.MockStakingKeeper, validator stakingtypes.Validator)
		skipDefaultGetValidator bool // when true, setup is responsible for registering GetValidator expectation
		msg                     *types.MsgSetNodePeerAddress
		expectErr               bool
		wantErrIs               error
		checkFunc               func(t *testing.T, f *fixture, validator stakingtypes.Validator)
	}{
		{
			name: "valid request sets peer address",
			msg: &types.MsgSetNodePeerAddress{
				Signer:      validSigner,
				PeerAddress: "abc123def456@192.168.1.10:26656",
			},
			expectErr: false,
			checkFunc: func(t *testing.T, f *fixture, validator stakingtypes.Validator) {
				stored, err := f.keeper.NodePeerAddresses.Get(f.ctx, validator.GetOperator())
				require.NoError(t, err)
				assert.Equal(t, "abc123def456@192.168.1.10:26656", stored)
			},
		},
		{
			name: "valid request overwrites existing peer address",
			setup: func(t *testing.T, f *fixture, _ *qbtctestutil.MockStakingKeeper, validator stakingtypes.Validator) {
				err := f.keeper.NodePeerAddresses.Set(f.ctx, validator.GetOperator(), "oldid@10.0.0.1:26656")
				require.NoError(t, err)
			},
			msg: &types.MsgSetNodePeerAddress{
				Signer:      validSigner,
				PeerAddress: "newid@10.0.0.2:26657",
			},
			expectErr: false,
			checkFunc: func(t *testing.T, f *fixture, validator stakingtypes.Validator) {
				stored, err := f.keeper.NodePeerAddresses.Get(f.ctx, validator.GetOperator())
				require.NoError(t, err)
				assert.Equal(t, "newid@10.0.0.2:26657", stored)
			},
		},
		{
			name: "empty signer fails validation",
			msg: &types.MsgSetNodePeerAddress{
				Signer:      "",
				PeerAddress: "abc123@192.168.1.1:26656",
			},
			expectErr: true,
			wantErrIs: sdkerrors.ErrInvalidAddress,
		},
		{
			name: "invalid signer bech32 fails validation",
			msg: &types.MsgSetNodePeerAddress{
				Signer:      "not-a-valid-bech32-address",
				PeerAddress: "abc123@192.168.1.1:26656",
			},
			expectErr: true,
			wantErrIs: sdkerrors.ErrInvalidAddress,
		},
		{
			name: "empty peer address fails validation",
			msg: &types.MsgSetNodePeerAddress{
				Signer:      validSigner,
				PeerAddress: "",
			},
			expectErr: true,
		},
		{
			name: "peer address without @ separator fails validation",
			msg: &types.MsgSetNodePeerAddress{
				Signer:      validSigner,
				PeerAddress: "abc123192.168.1.1:26656",
			},
			expectErr: true,
		},
		{
			name: "peer address with empty peer ID fails validation",
			msg: &types.MsgSetNodePeerAddress{
				Signer:      validSigner,
				PeerAddress: "@192.168.1.1:26656",
			},
			expectErr: true,
		},
		{
			name: "peer address without port fails validation",
			msg: &types.MsgSetNodePeerAddress{
				Signer:      validSigner,
				PeerAddress: "abc123@192.168.1.1",
			},
			expectErr: true,
		},
		{
			name: "peer address with empty host fails validation",
			msg: &types.MsgSetNodePeerAddress{
				Signer:      validSigner,
				PeerAddress: "abc123@:26656",
			},
			expectErr: true,
		},
		{
			name:                    "validator not found returns error",
			skipDefaultGetValidator: true,
			setup: func(_ *testing.T, _ *fixture, stakingKeeper *qbtctestutil.MockStakingKeeper, _ stakingtypes.Validator) {
				stakingKeeper.EXPECT().
					GetValidator(gomock.Any(), gomock.Any()).
					Return(stakingtypes.Validator{}, errors.New("validator not found")).
					AnyTimes()
			},
			msg: &types.MsgSetNodePeerAddress{
				Signer:      validSigner,
				PeerAddress: "abc123@192.168.1.1:26656",
			},
			expectErr: true,
		},
		{
			name:                    "unbonded validator is rejected with unauthorized",
			skipDefaultGetValidator: true,
			setup: func(_ *testing.T, _ *fixture, stakingKeeper *qbtctestutil.MockStakingKeeper, validator stakingtypes.Validator) {
				unbonded := validator
				unbonded.Status = stakingtypes.Unbonded
				stakingKeeper.EXPECT().
					GetValidator(gomock.Any(), gomock.Any()).
					Return(unbonded, nil).
					AnyTimes()
			},
			msg: &types.MsgSetNodePeerAddress{
				Signer:      validSigner,
				PeerAddress: "abc123@192.168.1.1:26656",
			},
			expectErr: true,
			wantErrIs: sdkerrors.ErrUnauthorized,
		},
		{
			name:                    "unbonding validator is rejected with unauthorized",
			skipDefaultGetValidator: true,
			setup: func(_ *testing.T, _ *fixture, stakingKeeper *qbtctestutil.MockStakingKeeper, validator stakingtypes.Validator) {
				unbonding := validator
				unbonding.Status = stakingtypes.Unbonding
				stakingKeeper.EXPECT().
					GetValidator(gomock.Any(), gomock.Any()).
					Return(unbonding, nil).
					AnyTimes()
			},
			msg: &types.MsgSetNodePeerAddress{
				Signer:      validSigner,
				PeerAddress: "abc123@192.168.1.1:26656",
			},
			expectErr: true,
			wantErrIs: sdkerrors.ErrUnauthorized,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
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
			if !tc.skipDefaultGetValidator {
				stakingKeeper.EXPECT().GetValidator(gomock.Any(), gomock.Any()).AnyTimes().Return(validator, nil)
			}
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
				tc.setup(t, f, stakingKeeper, validator)
			}

			server := keeper.NewMsgServerImpl(f.keeper)
			resp, err := server.SetNodePeerAddress(f.ctx, tc.msg)

			if tc.expectErr {
				assert.Error(t, err)
				assert.Nil(t, resp)
				if tc.wantErrIs != nil {
					assert.ErrorIs(t, err, tc.wantErrIs)
				}
			} else {
				assert.NoError(t, err)
				assert.Equal(t, &types.MsgEmpty{}, resp)
				if tc.checkFunc != nil {
					tc.checkFunc(t, f, validator)
				}
			}
		})
	}
}
