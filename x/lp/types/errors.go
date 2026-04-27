package types

import "cosmossdk.io/errors"

var (
	ErrInvalidAuthority    = errors.Register(ModuleName, 1100, "invalid authority")
	ErrUnknownParam        = errors.Register(ModuleName, 1101, "unknown parameter key")
	ErrInvalidBasisPoints  = errors.Register(ModuleName, 1102, "basis points must be in [1, 10000]")
	ErrInvalidDenom        = errors.Register(ModuleName, 1103, "denom not supported by lp module")
	ErrPoolNotAvailable    = errors.Register(ModuleName, 1104, "pool not in Available status")
	ErrLPNotFound          = errors.Register(ModuleName, 1105, "liquidity provider not found")
	ErrPendingAddNotFound  = errors.Register(ModuleName, 1106, "pending add not found")
	ErrPendingAddOpen      = errors.Register(ModuleName, 1107, "node already has an open pending add")
	ErrBondInsufficient    = errors.Register(ModuleName, 1110, "bonded units below request")
	ErrBTCAddressMismatch  = errors.Register(ModuleName, 1112, "btc address does not match LP record")
	ErrInvalidProof        = errors.Register(ModuleName, 1113, "zk proof verification failed")
	ErrSignerNotNode       = errors.Register(ModuleName, 1114, "signer is not a node operator or bond provider")
	ErrInvalidPair         = errors.Register(ModuleName, 1115, "swap source/dest denom pair not supported")
)
