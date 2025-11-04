package types

import (
	"cosmossdk.io/x/tx/signing"
	codectypes "github.com/cosmos/cosmos-sdk/codec/types"
	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/cosmos/cosmos-sdk/types/msgservice"
)

func RegisterInterfaces(registrar codectypes.InterfaceRegistry) {
	registrar.RegisterImplementations((*sdk.Msg)(nil))

	msgservice.RegisterMsgServiceDesc(registrar, &_Msg_serviceDesc)
}
func DefineCustomGetSigners(signingOptions *signing.Options) {
	//signingOptions.DefineCustomGetSigners(protoreflect.FullName("qbtc.qbtc.v1.MsgMimir"), MsgMimirCustomGetSigners)
}
