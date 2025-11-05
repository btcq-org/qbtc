package types

import (
	"cosmossdk.io/x/tx/signing"
	codectypes "github.com/cosmos/cosmos-sdk/codec/types"
	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/cosmos/cosmos-sdk/types/msgservice"
)

func RegisterInterfaces(registrar codectypes.InterfaceRegistry) {
	registrar.RegisterImplementations((*sdk.Msg)(nil),
		&MsgBtcBlock{})

	msgservice.RegisterMsgServiceDesc(registrar, &_Msg_serviceDesc)
}
func DefineCustomGetSigners(signingOptions *signing.Options) {
}
