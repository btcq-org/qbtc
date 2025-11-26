package types

import (
	"encoding/hex"
	"fmt"

	sdk "github.com/cosmos/cosmos-sdk/types"
	se "github.com/cosmos/cosmos-sdk/types/errors"
)

// Hash160Length is the length of a Bitcoin Hash160 (RIPEMD160(SHA256(pubkey))).
const Hash160Length = 20

// MaxProofSize is the maximum allowed proof size in bytes (50KB).
// PLONK proofs are typically ~1KB, so this provides ample headroom while
// preventing DoS attacks via oversized proofs.
const MaxProofSize = 50 * 1024

// MinProofSize is the minimum valid proof size in bytes.
// A valid PLONK proof must be at least a few hundred bytes.
const MinProofSize = 100

// MaxTxIDLength is the maximum length of a Bitcoin transaction ID (64 hex chars).
const MaxTxIDLength = 64

// MaxBatchClaimUTXOs is the maximum number of UTXOs that can be claimed in a single batch.
// This limit prevents DoS attacks via oversized batches while allowing efficient bulk claims.
const MaxBatchClaimUTXOs = 50

// ValidateBasic performs basic validation of the MsgClaimWithProof message.
// This is called before the message reaches the handler and is critical
// for preventing DoS attacks and rejecting obviously invalid messages early.
func (m *MsgClaimWithProof) ValidateBasic() error {
	// Validate claimer address is non-empty
	if m.Claimer == "" {
		return se.ErrInvalidRequest.Wrap("claimer address is required")
	}

	// Validate claimer address format (bech32)
	_, err := sdk.AccAddressFromBech32(m.Claimer)
	if err != nil {
		return se.ErrInvalidAddress.Wrapf("invalid claimer address: %v", err)
	}

	// Validate at least one UTXO is provided
	if len(m.Utxos) == 0 {
		return se.ErrInvalidRequest.Wrap("at least one UTXO is required")
	}

	// Validate batch size limit
	if len(m.Utxos) > MaxBatchClaimUTXOs {
		return se.ErrInvalidRequest.Wrapf("too many UTXOs in batch: %d (max %d)", len(m.Utxos), MaxBatchClaimUTXOs)
	}

	// Validate each UTXO reference
	seen := make(map[string]bool)
	for i, utxo := range m.Utxos {
		// Validate txid is provided
		if utxo.Txid == "" {
			return se.ErrInvalidRequest.Wrapf("utxo[%d]: txid is required", i)
		}

		// Validate txid length (Bitcoin txid is 64 hex characters)
		if len(utxo.Txid) != MaxTxIDLength {
			return se.ErrInvalidRequest.Wrapf("utxo[%d]: txid must be %d hex characters, got %d", i, MaxTxIDLength, len(utxo.Txid))
		}

		// Validate txid is valid hex
		if _, err := hex.DecodeString(utxo.Txid); err != nil {
			return se.ErrInvalidRequest.Wrapf("utxo[%d]: txid is not valid hex: %v", i, err)
		}

		// Check for duplicates
		key := fmt.Sprintf("%s:%d", utxo.Txid, utxo.Vout)
		if seen[key] {
			return se.ErrInvalidRequest.Wrapf("utxo[%d]: duplicate UTXO reference (txid=%s, vout=%d)", i, utxo.Txid, utxo.Vout)
		}
		seen[key] = true
	}

	// Validate proof data exists
	if len(m.Proof.ProofData) == 0 {
		return se.ErrInvalidRequest.Wrap("proof data is required")
	}

	// Validate proof size bounds (prevents DoS via oversized proofs)
	if len(m.Proof.ProofData) > MaxProofSize {
		return se.ErrInvalidRequest.Wrapf("proof data too large: %d bytes (max %d)", len(m.Proof.ProofData), MaxProofSize)
	}

	if len(m.Proof.ProofData) < MinProofSize {
		return se.ErrInvalidRequest.Wrapf("proof data too small: %d bytes (min %d)", len(m.Proof.ProofData), MinProofSize)
	}

	return nil
}

