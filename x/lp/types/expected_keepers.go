package types

import (
	"context"

	"cosmossdk.io/core/address"
	"cosmossdk.io/math"
	sdk "github.com/cosmos/cosmos-sdk/types"
	stakingtypes "github.com/cosmos/cosmos-sdk/x/staking/types"
)

// AuthKeeper is the subset of x/auth used by x/lp.
type AuthKeeper interface {
	AddressCodec() address.Codec
	GetModuleAddress(name string) sdk.AccAddress
	GetAccount(context.Context, sdk.AccAddress) sdk.AccountI
}

// BankKeeper is the subset of x/bank used by x/lp.
type BankKeeper interface {
	GetBalance(ctx context.Context, addr sdk.AccAddress, denom string) sdk.Coin
	GetSupply(ctx context.Context, denom string) sdk.Coin
	SpendableCoins(context.Context, sdk.AccAddress) sdk.Coins
	MintCoins(ctx context.Context, moduleName string, amt sdk.Coins) error
	BurnCoins(ctx context.Context, moduleName string, amt sdk.Coins) error
	SendCoinsFromAccountToModule(ctx context.Context, sender sdk.AccAddress, recipientModule string, amt sdk.Coins) error
	SendCoinsFromModuleToAccount(ctx context.Context, senderModule string, recipientAddr sdk.AccAddress, amt sdk.Coins) error
	SendCoinsFromModuleToModule(ctx context.Context, senderModule, recipientModule string, amt sdk.Coins) error
}

// StakingKeeper is the subset of x/staking used by x/lp (validator-set
// awareness for bond/unbond gating and observation quorum).
type StakingKeeper interface {
	GetValidator(context.Context, sdk.ValAddress) (stakingtypes.Validator, error)
	GetBondedValidatorsByPower(ctx context.Context) ([]stakingtypes.Validator, error)
	GetLastTotalPower(ctx context.Context) (math.Int, error)
	PowerReduction(ctx context.Context) math.Int
}

// SecuredKeeper is the surface x/lp consumes from x/secured: mint sbtc into a
// holding account on observation, and burn sbtc + queue a BTC outbound on
// withdraw / swap-out / refund.
type SecuredKeeper interface {
	MintSecured(ctx context.Context, amount math.Uint, refID string) error
	BurnSecuredAndQueueOutbound(ctx context.Context, amount math.Uint, destBTCAddress, memo, refID string) (uint64, error)
	OutboundEnabled(ctx context.Context) bool
}
