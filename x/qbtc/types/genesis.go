package types

import (
	"bytes"
	"fmt"

	"github.com/btcq-org/qbtc/x/qbtc/zk"
	"github.com/btcsuite/btcd/blockchain"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/wire"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/plonk"
)

// MinVerifyingKeySize is the minimum valid verifying key size.
// A valid PLONK verifying key for BN254 is typically tens of kilobytes.
// Empirically, even a minimal circuit (1 constraint) produces a VK of ~34KB.
// We set a conservative lower bound to catch obviously truncated/invalid keys.
const MinVerifyingKeySize = 1024

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
	// Validate ZK verifying key if present
	if len(gs.ZkVerifyingKey) > 0 {
		if err := ValidateVerifyingKey(gs.ZkVerifyingKey); err != nil {
			return fmt.Errorf("invalid zk_verifying_key: %w", err)
		}
	}

	if err := gs.validateBtcAnchor(); err != nil {
		return err
	}

	return nil
}

// ValidateVerifyingKey validates that the verifying key bytes are well-formed.
// This ensures the VK can be deserialized, is within size bounds, was set up
// from the Hermez Powers of Tau, and has the claim circuit's public inputs.
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

	// Reject keys from the unsafe test SRS or with the wrong number of public inputs
	return zk.ValidateClaimVerifyingKey(vk)
}

// validateBtcAnchor checks the anchor header against Bitcoin mainnet's
// proof-of-work limit. A chain that processes Bitcoin blocks
// (btc_initial_height > 0) needs an anchor, or the first block could link to
// anything.
func (gs GenesisState) validateBtcAnchor() error {
	if len(gs.BtcAnchorHeader) == 0 {
		if gs.BtcInitialHeight > 0 {
			return fmt.Errorf("btc_anchor_header is required when btc_initial_height is set")
		}
		return nil
	}
	if gs.BtcInitialHeight == 0 {
		return fmt.Errorf("btc_initial_height is required with btc_anchor_header")
	}
	var header wire.BlockHeader
	if len(gs.BtcAnchorHeader) != BtcHeaderSize {
		return fmt.Errorf("btc_anchor_header is %d bytes, want %d", len(gs.BtcAnchorHeader), BtcHeaderSize)
	}
	if err := header.Deserialize(bytes.NewReader(gs.BtcAnchorHeader)); err != nil {
		return fmt.Errorf("invalid btc_anchor_header: %w", err)
	}
	hash := header.BlockHash()
	target := blockchain.CompactToBig(header.Bits)
	if target.Sign() <= 0 || target.Cmp(chaincfg.MainNetParams.PowLimit) > 0 || blockchain.HashToBig(&hash).Cmp(target) > 0 {
		return fmt.Errorf("btc_anchor_header %s does not meet its proof-of-work target", hash)
	}
	if gs.BtcAnchorPeriodStartTime == 0 || int64(gs.BtcAnchorPeriodStartTime) > header.Timestamp.Unix() {
		return fmt.Errorf("btc_anchor_period_start_time must be set and not after the anchor's timestamp")
	}
	return nil
}
