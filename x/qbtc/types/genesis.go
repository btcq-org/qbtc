package types

import (
	"bytes"
	"fmt"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/plonk"
	sdk "github.com/cosmos/cosmos-sdk/types"
)

// MinVerifyingKeySize is the minimum valid verifying key size.
// A valid PLONK verifying key for BN254 should be at least a few hundred bytes.
const MinVerifyingKeySize = 100

// MaxVerifyingKeySize is the maximum allowed verifying key size (1MB).
// This prevents DoS via oversized VK in genesis.
const MaxVerifyingKeySize = 1024 * 1024

// DefaultGenesis returns the default genesis state
func DefaultGenesis() *GenesisState {
	return &GenesisState{}
}

// Validate performs basic genesis state validation returning an error upon any
// failure.
func (gs GenesisState) Validate() error {
	for _, nodePeerAddress := range gs.PeerAddresses {
		if nodePeerAddress.Validator == "" {
			return fmt.Errorf("validator cannot be empty")
		}
		_, err := sdk.ValAddressFromBech32(nodePeerAddress.Validator)
		if err != nil {
			return fmt.Errorf("invalid validator address: %s", err)
		}
		if err := ValidatePeerAddress(nodePeerAddress.PeerAddress); err != nil {
			return fmt.Errorf("invalid peer address: %w", err)
		}
	}

	// Validate airdrop entries
	seenHashes := make(map[string]bool)
	for i, entry := range gs.AirdropEntries {
		if len(entry.AddressHash) != Hash160Length {
			return fmt.Errorf("airdrop entry %d: invalid address hash length, expected %d bytes, got %d",
				i, Hash160Length, len(entry.AddressHash))
		}
		hashKey := string(entry.AddressHash)
		if seenHashes[hashKey] {
			return fmt.Errorf("airdrop entry %d: duplicate address hash", i)
		}
		seenHashes[hashKey] = true
	}

	// Validate ZK verifying key if present
	if len(gs.ZkVerifyingKey) > 0 {
		if err := ValidateVerifyingKey(gs.ZkVerifyingKey); err != nil {
			return fmt.Errorf("invalid zk_verifying_key: %w", err)
		}
	}

	return nil
}

// ValidateVerifyingKey validates that the verifying key bytes are well-formed.
// This ensures the VK can be deserialized and is within size bounds.
func ValidateVerifyingKey(vkBytes []byte) error {
	// Check size bounds
	if len(vkBytes) < MinVerifyingKeySize {
		return fmt.Errorf("verifying key too small: %d bytes (min %d)", len(vkBytes), MinVerifyingKeySize)
	}
	if len(vkBytes) > MaxVerifyingKeySize {
		return fmt.Errorf("verifying key too large: %d bytes (max %d)", len(vkBytes), MaxVerifyingKeySize)
	}

	// Attempt to deserialize to validate format
	vk := plonk.NewVerifyingKey(ecc.BN254)
	_, err := vk.ReadFrom(bytes.NewReader(vkBytes))
	if err != nil {
		return fmt.Errorf("failed to deserialize verifying key: %w", err)
	}

	return nil
}
