package config

import (
	"context"

	"google.golang.org/grpc/codes"
	grpcstatus "google.golang.org/grpc/status"
	"google.golang.org/protobuf/reflect/protoreflect"

	bankv1beta1 "cosmossdk.io/api/cosmos/bank/v1beta1"
	txconfigv1 "cosmossdk.io/api/cosmos/tx/config/v1"
	"cosmossdk.io/core/address"
	"cosmossdk.io/core/appmodule"
	"cosmossdk.io/depinject"
	txsigning "cosmossdk.io/x/tx/signing"
	"cosmossdk.io/x/tx/signing/textual"

	"github.com/cosmos/cosmos-sdk/baseapp"
	"github.com/cosmos/cosmos-sdk/client"
	"github.com/cosmos/cosmos-sdk/codec"
	"github.com/cosmos/cosmos-sdk/runtime"
	"github.com/cosmos/cosmos-sdk/types/registry"
	signingtypes "github.com/cosmos/cosmos-sdk/types/tx/signing"
	"github.com/cosmos/cosmos-sdk/x/auth/ante"
	"github.com/cosmos/cosmos-sdk/x/auth/tx"
	authtypes "github.com/cosmos/cosmos-sdk/x/auth/types"
	"github.com/cosmos/cosmos-sdk/x/bank/types"

	"github.com/btcq-org/qbtc/x/qbtc/ebifrost"
)

func init() {
	appmodule.Register(&txconfigv1.Config{},
		appmodule.Provide(ProvideModule),
		appmodule.Provide(ProvideProtoRegistry),
	)
}

// BankKeeper defines the contract needed for tx-related APIs
type BankKeeper interface {
	DenomMetadata(c context.Context, req *types.QueryDenomMetadataRequest) (*types.QueryDenomMetadataResponse, error)
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
	MetadataBankKeeper     BankKeeper                         `optional:"true"`
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
		ProtoEncoder:    ebifrost.TxEncoder(tx.DefaultTxEncoder()),
		ProtoDecoder:    ebifrost.TxDecoder(in.Codec, tx.DefaultTxDecoder(in.Codec)),
		JSONEncoder:     ebifrost.JSONTxEncoder(in.Codec, tx.DefaultJSONTxEncoder(in.Codec)),
		JSONDecoder:     ebifrost.JSONTxDecoder(in.Codec, tx.DefaultJSONTxDecoder(in.Codec)),
	}

	for _, mode := range in.CustomGetSigners {
		txConfigOptions.SigningOptions.CustomGetSigners[mode.MsgType] = mode.Fn
	}

	// enable SIGN_MODE_TEXTUAL only if bank keeper is available
	if in.MetadataBankKeeper != nil {
		txConfigOptions.EnabledSignModes = append(txConfigOptions.EnabledSignModes, signingtypes.SignMode_SIGN_MODE_TEXTUAL)
		txConfigOptions.TextualCoinMetadataQueryFn = NewBankKeeperCoinMetadataQueryFn(in.MetadataBankKeeper)
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

// NewBankKeeperCoinMetadataQueryFn creates a new Textual struct using the given
// BankKeeper to retrieve coin metadata.
//
// This function should be used in the server (app.go) and is already injected thanks to app wiring for app_v2.
func NewBankKeeperCoinMetadataQueryFn(bk BankKeeper) textual.CoinMetadataQueryFn {
	return func(ctx context.Context, denom string) (*bankv1beta1.Metadata, error) {
		res, err := bk.DenomMetadata(ctx, &types.QueryDenomMetadataRequest{Denom: denom})
		if err != nil {
			return nil, metadataExists(err)
		}

		m := &bankv1beta1.Metadata{
			Base:    res.Metadata.Base,
			Display: res.Metadata.Display,
			// fields below are not strictly needed by Textual
			// but added here for completeness.
			Description: res.Metadata.Description,
			Name:        res.Metadata.Name,
			Symbol:      res.Metadata.Symbol,
			Uri:         res.Metadata.URI,
			UriHash:     res.Metadata.URIHash,
		}
		m.DenomUnits = make([]*bankv1beta1.DenomUnit, len(res.Metadata.DenomUnits))
		for i, d := range res.Metadata.DenomUnits {
			m.DenomUnits[i] = &bankv1beta1.DenomUnit{
				Denom:    d.Denom,
				Exponent: d.Exponent,
				Aliases:  d.Aliases,
			}
		}

		return m, nil
	}
}

// metadataExists parses the error, and only propagates the error if it's
// different than a "not found" error.
func metadataExists(err error) error {
	status, ok := grpcstatus.FromError(err)
	if !ok {
		return err
	}

	// This means we didn't find any metadata for this denom. Returning
	// empty metadata.
	if status.Code() == codes.NotFound {
		return nil
	}

	return err
}
