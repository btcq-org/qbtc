package types

import (
	"context"

	"cosmossdk.io/core/address"
	"cosmossdk.io/math"
	sdk "github.com/cosmos/cosmos-sdk/types"
	stakingtypes "github.com/cosmos/cosmos-sdk/x/staking/types"
)

type AuthKeeper interface {
	AddressCodec() address.Codec
	GetModuleAddress(name string) sdk.AccAddress
}

type BankKeeper interface {
	MintCoins(ctx context.Context, moduleName string, amt sdk.Coins) error
	BurnCoins(ctx context.Context, moduleName string, amt sdk.Coins) error
	SendCoinsFromModuleToAccount(ctx context.Context, senderModule string, recipientAddr sdk.AccAddress, amt sdk.Coins) error
	SendCoinsFromModuleToModule(ctx context.Context, senderModule, recipientModule string, amt sdk.Coins) error
	GetBalance(ctx context.Context, addr sdk.AccAddress, denom string) sdk.Coin
}

type StakingKeeper interface {
	GetValidator(context.Context, sdk.ValAddress) (stakingtypes.Validator, error)
	GetBondedValidatorsByPower(ctx context.Context) ([]stakingtypes.Validator, error)
	GetLastTotalPower(ctx context.Context) (math.Int, error)
	PowerReduction(ctx context.Context) math.Int
}

// LPHooks is the surface x/lp registers with x/secured. After an inbound is
// finalized and sbtc minted to the holding account, x/secured invokes one of
// these hooks based on memo prefix; a nil hook means routing is disabled and
// the inbound is refunded.
type LPHooks interface {
	OnObservedAddLiquidity(ctx context.Context, pendingID uint64, sats math.Uint, txid string) error
	OnObservedSwapToQbtc(ctx context.Context, sats math.Uint, destCosmosAddr string, minOut math.Uint, txid, btcSender string) error
}
