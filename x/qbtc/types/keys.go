package types

import "cosmossdk.io/collections"

const (
	// ModuleName defines the module name
	ModuleName = "qbtc"

	// StoreKey defines the primary module store key
	StoreKey = ModuleName

	// GovModuleName duplicates the gov module's name to avoid a dependency with x/gov.
	// It should be synced with the gov module's name if it is ever changed.
	// See: https://github.com/cosmos/cosmos-sdk/blob/v0.52.0-beta.2/x/gov/types/keys.go#L9
	GovModuleName = "gov"

	ReserveModuleName = "reserve"
)

var (
	// UTXOKeys is the prefix for UTXO store
	UTXOKeys = collections.NewPrefix("utxo")

	// ConstOverrideKeys is the prefix for constant overrides
	ConstOverrideKeys = collections.NewPrefix("const_override")

	// StringParamKeys is the prefix for string-valued governance parameters
	StringParamKeys = collections.NewPrefix("string_param")

	// ZkVerifyingKeyKey stores the PLONK verifying key for ZK proof verification
	ZkVerifyingKeyKey = collections.NewPrefix("zk_verifying_key")

	// LastProcessedBlockKey stores the last processed block height
	LastProcessedBlockKey = collections.NewPrefix("last_processed_block")

	// BtcTipHeaderKey stores the 80-byte header of the last processed Bitcoin
	// block (or of the genesis anchor); the next block must link to it.
	BtcTipHeaderKey = collections.NewPrefix("btc_tip_header")

	// BtcPeriodStartTimeKey stores the timestamp of the first block of the
	// tip's difficulty period.
	BtcPeriodStartTimeKey = collections.NewPrefix("btc_period_start_time")
)

const (
	// String parameter keys for governance-controlled addresses.
	DevFundAddressKey       = "DevFundAddress"
	MarketingFundAddressKey = "MarketingFundAddress"
)

const (
	EventTypeUpdateParam = "update_param"

	AttributeKeyParamKey   = "param_key"
	AttributeKeyParamValue = "param_value"

	EventTypeGovClaimUTXO           = "gov_claim_utxo"
	AttributeKeyUTXOCount           = "utxo_count"
	AttributeKeyGovClaimer          = "gov_claimer"
	AttributeUtxos                  = "utxos"
	AttributeKeyDevFundAmount       = "dev_fund_amount"
	AttributeKeyMarketingFundAmount = "marketing_fund_amount"
	AttributeKeyReserveAmount       = "reserve_amount"
)
