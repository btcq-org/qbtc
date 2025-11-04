package app

import (
	"github.com/btcq-org/qbtc/common"
	sdk "github.com/cosmos/cosmos-sdk/types"
)

func init() {
	// Set bond denom

	sdk.DefaultBondDenom = "qbtc"

	// Set address prefixes
	accountPubKeyPrefix := common.AccountAddressPrefix + "pub"
	validatorAddressPrefix := common.AccountAddressPrefix + "valoper"
	validatorPubKeyPrefix := common.AccountAddressPrefix + "valoperpub"
	consNodeAddressPrefix := common.AccountAddressPrefix + "valcons"
	consNodePubKeyPrefix := common.AccountAddressPrefix + "valconspub"

	// Set and seal config
	config := sdk.GetConfig()
	config.SetCoinType(ChainCoinType)
	config.SetBech32PrefixForAccount(common.AccountAddressPrefix, accountPubKeyPrefix)
	config.SetBech32PrefixForValidator(validatorAddressPrefix, validatorPubKeyPrefix)
	config.SetBech32PrefixForConsensusNode(consNodeAddressPrefix, consNodePubKeyPrefix)
	config.Seal()
}
