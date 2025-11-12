package keeper_test

import (
	"context"
	"testing"

	"cosmossdk.io/core/address"
	storetypes "cosmossdk.io/store/types"
	"github.com/btcq-org/qbtc/common"
	"github.com/btcq-org/qbtc/x/qbtc/keeper"
	module "github.com/btcq-org/qbtc/x/qbtc/module"
	"github.com/btcq-org/qbtc/x/qbtc/types"
	"github.com/cometbft/cometbft/crypto/mldsa"
	addresscodec "github.com/cosmos/cosmos-sdk/codec/address"
	"github.com/cosmos/cosmos-sdk/runtime"
	"github.com/cosmos/cosmos-sdk/testutil"
	sdk "github.com/cosmos/cosmos-sdk/types"
	moduletestutil "github.com/cosmos/cosmos-sdk/types/module/testutil"
)

type fixture struct {
	ctx          context.Context
	keeper       keeper.Keeper
	addressCodec address.Codec
}

func initFixture(t *testing.T) *fixture {
	t.Helper()
	sdk.GetConfig().SetBech32PrefixForAccount(common.AccountAddressPrefix, common.AccountAddressPrefix+sdk.PrefixPublic)
	encCfg := moduletestutil.MakeTestEncodingConfig(module.AppModule{})
	addressCodec := addresscodec.NewBech32Codec(common.AccountAddressPrefix)
	storeKey := storetypes.NewKVStoreKey(types.StoreKey)

	storeService := runtime.NewKVStoreService(storeKey)
	ctx := testutil.DefaultContextWithDB(t, storeKey, storetypes.NewTransientStoreKey("transient_test")).Ctx

	k := keeper.NewKeeper(
		storeService,
		encCfg.Codec,
		addressCodec,
		nil,
	)

	return &fixture{
		ctx:          ctx,
		keeper:       k,
		addressCodec: addressCodec,
	}
}
func (f *fixture) GetAddressFromPubKey(pubKey []byte) (string, error) {
	return f.addressCodec.BytesToString(pubKey)
}
func (f *fixture) GetRandomQbtcAddress() (string, error) {
	privateKey := mldsa.GenPrivKey()
	pubKey := privateKey.PubKey()
	return f.GetAddressFromPubKey(pubKey.Address().Bytes())
}
