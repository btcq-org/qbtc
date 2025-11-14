package keeper_test

import (
	"context"
	"testing"

	"cosmossdk.io/core/address"
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
)

type fixture struct {
	ctx                   context.Context
	keeper                keeper.Keeper
	addressCodec          address.Codec
	validatorAddressCodec address.Codec
	validator             stakingtypes.Validator
	privateKey            mldsa.PrivKey
}

func initFixture(t *testing.T) *fixture {
	t.Helper()
	sdk.GetConfig().SetBech32PrefixForAccount(common.AccountAddressPrefix, common.AccountAddressPrefix+sdk.PrefixPublic)
	sdk.GetConfig().SetBech32PrefixForValidator(common.AccountAddressPrefix+sdk.PrefixValidator, common.AccountAddressPrefix+sdk.PrefixPublic)
	encCfg := moduletestutil.MakeTestEncodingConfig(module.AppModule{})
	addressCodec := addresscodec.NewBech32Codec(common.AccountAddressPrefix)
	validatorAddressCodec := addresscodec.NewBech32Codec(common.AccountAddressPrefix + sdk.PrefixValidator)
	storeKey := storetypes.NewKVStoreKey(types.StoreKey)

	storeService := runtime.NewKVStoreService(storeKey)
	ctx := testutil.DefaultContextWithDB(t, storeKey, storetypes.NewTransientStoreKey("transient_test")).Ctx
	ctrl := gomock.NewController(t)
	stakingKeeper := qbtctestutil.NewMockStakingKeeper(ctrl)

	privateKey := mldsa.GenPrivKey()
	pubKey := privateKey.PubKey()
	pKey, err := codec.FromCmtPubKeyInterface(pubKey)
	assert.NoError(t, err)
	validator, err := stakingtypes.NewValidator("", pKey, stakingtypes.Description{})
	assert.NoError(t, err)
	validator.Status = stakingtypes.Bonded
	validator.Tokens = math.NewInt(1000000000)

	stakingKeeper.EXPECT().GetLastTotalPower(gomock.Any()).AnyTimes().Return(math.NewInt(1000000), nil)
	stakingKeeper.EXPECT().GetValidator(gomock.Any(), gomock.Any()).AnyTimes().Return(validator, nil)
	stakingKeeper.EXPECT().PowerReduction(gomock.Any()).AnyTimes().Return(math.NewInt(1000))

	bankKeeper := qbtctestutil.NewMockBankKeeper(ctrl)
	k := keeper.NewKeeper(
		storeService,
		encCfg.Codec,
		addressCodec,
		stakingKeeper,
		bankKeeper,
		govtypes.ModuleName,
	)

	return &fixture{
		ctx:                   ctx,
		keeper:                k,
		addressCodec:          addressCodec,
		validator:             validator,
		privateKey:            privateKey,
		validatorAddressCodec: validatorAddressCodec,
	}
}
func (f *fixture) GetAddressFromPubKey(pubKey []byte) (string, error) {
	return f.addressCodec.BytesToString(pubKey)
}
func (f *fixture) GetValidatorAddress(pubKey []byte) (string, error) {
	return f.validatorAddressCodec.BytesToString(pubKey)
}
func (f *fixture) GetRandomQbtcAddress() (string, error) {
	privateKey := mldsa.GenPrivKey()
	pubKey := privateKey.PubKey()
	return f.GetAddressFromPubKey(pubKey.Address().Bytes())
}
