package types

import (
	"cosmossdk.io/x/tx/signing"
	codectypes "github.com/cosmos/cosmos-sdk/codec/types"
	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/cosmos/cosmos-sdk/types/msgservice"
)

func RegisterInterfaces(registrar codectypes.InterfaceRegistry) {
	registrar.RegisterImplementations((*sdk.Msg)(nil),
		&MsgAddLiquidity{},
		&MsgWithdrawLiquidity{},
		&MsgSwap{},
		&MsgBond{},
		&MsgUnbond{},
		&MsgUpdateParam{},
	)
	msgservice.RegisterMsgServiceDesc(registrar, &_Msg_serviceDesc)
}

func DefineCustomGetSigners(_ *signing.Options) {}
