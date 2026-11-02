package config

import (
	"google.golang.org/protobuf/reflect/protoreflect"

	txconfigv1 "cosmossdk.io/api/cosmos/tx/config/v1"
	"cosmossdk.io/core/address"
	"cosmossdk.io/core/appmodule"
	"cosmossdk.io/depinject"
	txsigning "github.com/cosmos/cosmos-sdk/x/tx/signing"

	"github.com/cosmos/cosmos-sdk/baseapp"
	"github.com/cosmos/cosmos-sdk/client"
	"github.com/cosmos/cosmos-sdk/codec"
	"github.com/cosmos/cosmos-sdk/runtime"
	"github.com/cosmos/cosmos-sdk/types/registry"
	"github.com/cosmos/cosmos-sdk/x/auth/ante"
	"github.com/cosmos/cosmos-sdk/x/auth/tx"
	authtypes "github.com/cosmos/cosmos-sdk/x/auth/types"

	"github.com/btcq-org/qbtc/x/qbtc/btcreader"
)

func init() {
	appmodule.Register(&txconfigv1.Config{},
		appmodule.Provide(ProvideModule),
		appmodule.Provide(ProvideProtoRegistry),
	)
}

type ModuleInputs struct {
	depinject.In

	Config                *txconfigv1.Config
	AddressCodec          address.Codec
	ValidatorAddressCodec runtime.ValidatorAddressCodec
	Codec                 codec.Codec
	ProtoFileResolver     txsigning.ProtoFileResolver
	// BankKeeper is the expected bank keeper to be passed to AnteHandlers
	BankKeeper             authtypes.BankKeeper               `optional:"true"`
	AccountKeeper          ante.AccountKeeper                 `optional:"true"`
	FeeGrantKeeper         ante.FeegrantKeeper                `optional:"true"`
	CustomSignModeHandlers func() []txsigning.SignModeHandler `optional:"true"`
	CustomGetSigners       []txsigning.CustomGetSigner        `optional:"true"`
}

type ModuleOutputs struct {
	depinject.Out

	TxConfig        client.TxConfig
	TxConfigOptions tx.ConfigOptions
	BaseAppOption   runtime.BaseAppOption
}

func ProvideProtoRegistry() txsigning.ProtoFileResolver {
	return registry.MergedProtoRegistry()
}

// ProvideModule provides the tx config module
// initial config from cosmos-sdk/x/tx/config
// adding custom tx encoder and decoding as well as setting the ante and post handlers
func ProvideModule(in ModuleInputs) ModuleOutputs {
	var customSignModeHandlers []txsigning.SignModeHandler
	if in.CustomSignModeHandlers != nil {
		customSignModeHandlers = in.CustomSignModeHandlers()
	}

	txConfigOptions := tx.ConfigOptions{
		EnabledSignModes: tx.DefaultSignModes,
		SigningOptions: &txsigning.Options{
			FileResolver:          in.ProtoFileResolver,
			AddressCodec:          in.AddressCodec,
			ValidatorAddressCodec: in.ValidatorAddressCodec,
			CustomGetSigners:      make(map[protoreflect.FullName]txsigning.GetSignersFunc),
		},
		CustomSignModes: customSignModeHandlers,
		ProtoEncoder:    btcreader.TxEncoder(tx.DefaultTxEncoder()),
		ProtoDecoder:    btcreader.TxDecoder(in.Codec, tx.DefaultTxDecoder(in.Codec)),
		JSONEncoder:     btcreader.JSONTxEncoder(in.Codec, tx.DefaultJSONTxEncoder(in.Codec)),
		JSONDecoder:     btcreader.JSONTxDecoder(in.Codec, tx.DefaultJSONTxDecoder(in.Codec)),
	}

	for _, mode := range in.CustomGetSigners {
		txConfigOptions.SigningOptions.CustomGetSigners[mode.MsgType] = mode.Fn
	}

	txConfig, err := tx.NewTxConfigWithOptions(in.Codec, txConfigOptions)
	if err != nil {
		panic(err)
	}

	baseAppOption := func(app *baseapp.BaseApp) {
		// TxDecoder/TxEncoder
		app.SetTxDecoder(txConfig.TxDecoder())
		app.SetTxEncoder(txConfig.TxEncoder())
	}

	return ModuleOutputs{TxConfig: txConfig, TxConfigOptions: txConfigOptions, BaseAppOption: baseAppOption}
}
