package types

import (
	codectypes "github.com/cosmos/cosmos-sdk/codec/types"
	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/cosmos/cosmos-sdk/types/msgservice"
	"github.com/cosmos/cosmos-sdk/x/tx/signing"
)

func RegisterInterfaces(registrar codectypes.InterfaceRegistry) {
	registrar.RegisterImplementations((*sdk.Msg)(nil),
		&MsgBtcBlock{},
		&MsgClaimWithProof{},
		&MsgGovClaimUTXO{},
		&MsgUpdateParam{},
		&MsgFundReferralPool{},
		&MsgDrainReferralPool{},
	)

	msgservice.RegisterMsgServiceDesc(registrar, &_Msg_serviceDesc)
}
func DefineCustomGetSigners(signingOptions *signing.Options) {
}
