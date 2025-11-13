package module

import (
	"encoding/json"

	"github.com/cosmos/cosmos-sdk/client"
	"github.com/cosmos/cosmos-sdk/codec"
	codectypes "github.com/cosmos/cosmos-sdk/codec/types"
	"github.com/grpc-ecosystem/grpc-gateway/runtime"
)

// Stub package to satisfy wasmd test imports
// Not used in production code

type AppModuleBasic struct{}

func (AppModuleBasic) Name() string                                    { return "group" }
func (AppModuleBasic) RegisterLegacyAminoCodec(*codec.LegacyAmino)     {}
func (AppModuleBasic) RegisterInterfaces(codectypes.InterfaceRegistry) {}
func (AppModuleBasic) DefaultGenesis(codec.JSONCodec) json.RawMessage  { return nil }
func (AppModuleBasic) ValidateGenesis(codec.JSONCodec, client.TxEncodingConfig, json.RawMessage) error {
	return nil
}
func (AppModuleBasic) RegisterGRPCGatewayRoutes(client.Context, *runtime.ServeMux) {}
