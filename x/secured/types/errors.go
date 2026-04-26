package types

import "cosmossdk.io/errors"

var (
	ErrInvalidAuthority   = errors.Register(ModuleName, 1100, "invalid authority")
	ErrUnknownParam       = errors.Register(ModuleName, 1101, "unknown parameter key")
	ErrInsufficientQuorum = errors.Register(ModuleName, 1102, "attestation power below quorum threshold")
	ErrTxOutNotFound      = errors.Register(ModuleName, 1103, "tx out item not found")
	ErrVaultNotInit       = errors.Register(ModuleName, 1104, "vault not initialized")
	ErrDuplicateObserved  = errors.Register(ModuleName, 1105, "tx already observed and finalized")
	ErrAttestationInvalid = errors.Register(ModuleName, 1106, "attestation address or signature invalid")
)
