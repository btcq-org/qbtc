package module

import (
	"cosmossdk.io/core/address"
	"cosmossdk.io/core/appmodule"
	"cosmossdk.io/core/store"
	"cosmossdk.io/depinject"
	"cosmossdk.io/depinject/appconfig"
	"github.com/cosmos/cosmos-sdk/codec"
	authtypes "github.com/cosmos/cosmos-sdk/x/auth/types"
	govtypes "github.com/cosmos/cosmos-sdk/x/gov/types"

	securedkeeper "github.com/btcq-org/qbtc/x/secured/keeper"

	"github.com/btcq-org/qbtc/x/lp/keeper"
	"github.com/btcq-org/qbtc/x/lp/types"
)

var _ depinject.OnePerModuleType = AppModule{}

func (AppModule) IsOnePerModuleType() {}

func init() {
	appconfig.Register(
		&types.Module{},
		appconfig.Provide(ProvideModule),
	)
}

type ModuleInputs struct {
	depinject.In

	Config       *types.Module
	StoreService store.KVStoreService
	Cdc          codec.Codec
	AddressCodec address.Codec

	AuthKeeper    types.AuthKeeper
	BankKeeper    types.BankKeeper
	StakingKeeper types.StakingKeeper

	// SecuredKeeper is taken as the concrete pointer (rather than the narrow
	// expected-keeper interface) because we need to call SetLPHooks on it
	// during wiring — the concrete keeper is the only thing that satisfies
	// both the runtime SecuredKeeper interface AND the wiring-time hook
	// registrar.
	SecuredKeeper *securedkeeper.Keeper
}

type ModuleOutputs struct {
	depinject.Out

	LpKeeper *keeper.Keeper
	Module   appmodule.AppModule
}

func ProvideModule(in ModuleInputs) ModuleOutputs {
	authority := authtypes.NewModuleAddress(govtypes.ModuleName)
	if in.Config.Authority != "" {
		authority = authtypes.NewModuleAddressOrBech32Address(in.Config.Authority)
	}
	k := keeper.NewKeeper(
		in.StoreService,
		in.Cdc,
		in.AddressCodec,
		in.AuthKeeper,
		in.BankKeeper,
		in.StakingKeeper,
		in.SecuredKeeper,
		authority.String(),
	)

	// Cross-module wiring: register x/lp's hook adapter with x/secured. After
	// this, MsgObservedTxIn finalizations route memo-bound observations into
	// the LP state machine.
	in.SecuredKeeper.SetLPHooks(keeper.NewLPHooks(k))

	m := NewAppModule(in.Cdc, k)
	return ModuleOutputs{LpKeeper: k, Module: m}
}
