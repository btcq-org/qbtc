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

// BitcoinTxIDLength is the length of a Bitcoin transaction id in raw bytes.
const BitcoinTxIDLength = 32

// MaxBatchClaimUTXOs is the maximum number of UTXOs that can be claimed in a single batch.
// This limit prevents DoS attacks via oversized batches while allowing efficient bulk claims.
const MaxBatchClaimUTXOs = 50

// ValidateBasic performs basic validation of the MsgClaimWithProof message.
// This is called before the message reaches the handler and is critical
// for preventing DoS attacks and rejecting obviously invalid messages early.
func (m *MsgClaimWithProof) ValidateBasic() error {
	if m.Claimer == "" {
		return se.ErrInvalidRequest.Wrap("claimer address is required")
	}

	if _, err := sdk.AccAddressFromBech32(m.Claimer); err != nil {
		return se.ErrInvalidAddress.Wrapf("invalid claimer address: %v", err)
	}

	if m.Receiver != "" {
		if _, err := sdk.AccAddressFromBech32(m.Receiver); err != nil {
			return se.ErrInvalidAddress.Wrapf("invalid receiver address: %v", err)
		}
	}

	if m.Broadcaster == "" {
		return se.ErrInvalidRequest.Wrap("broadcaster address is required")
	}
	if _, err := sdk.AccAddressFromBech32(m.Broadcaster); err != nil {
		return se.ErrInvalidAddress.Wrapf("invalid broadcaster address: %v", err)
	}

	if len(m.Utxos) == 0 {
		return se.ErrInvalidRequest.Wrap("at least one UTXO is required")
	}

	if len(m.Utxos) > MaxBatchClaimUTXOs {
		return se.ErrInvalidRequest.Wrapf("too many UTXOs in batch: %d (max %d)", len(m.Utxos), MaxBatchClaimUTXOs)
	}

	seen := make(map[string]bool)
	for i, utxo := range m.Utxos {
		if len(utxo.Txid) != BitcoinTxIDLength {
			return se.ErrInvalidRequest.Wrapf("utxo[%d]: txid must be %d bytes, got %d", i, BitcoinTxIDLength, len(utxo.Txid))
		}

		key := fmt.Sprintf("%x:%d", utxo.Txid, utxo.Vout)
		if seen[key] {
			return se.ErrInvalidRequest.Wrapf("utxo[%d]: duplicate UTXO reference (txid=%x, vout=%d)", i, utxo.Txid, utxo.Vout)
		}
		seen[key] = true
	}

	if len(m.Proof) == 0 {
		return se.ErrInvalidRequest.Wrap("proof data is required")
	}
	proofBytes, err := hex.DecodeString(m.Proof)
	if err != nil {
		return se.ErrInvalidRequest.Wrapf("proof data is not valid hex: %v", err)
	}
	if len(proofBytes) > MaxProofSize {
		return se.ErrInvalidRequest.Wrapf("proof data too large: %d bytes (max %d)", len(proofBytes), MaxProofSize)
	}
	if len(proofBytes) < MinProofSize {
		return se.ErrInvalidRequest.Wrapf("proof data too small: %d bytes (min %d)", len(proofBytes), MinProofSize)
	}

	if len(m.MessageHash) != 64 {
		return se.ErrInvalidRequest.Wrapf("message_hash must be 64 hex characters, got %d", len(m.MessageHash))
	}
	if _, err := hex.DecodeString(m.MessageHash); err != nil {
		return se.ErrInvalidRequest.Wrapf("message_hash is not valid hex: %v", err)
	}
	if len(m.AddressHash) != 40 {
		return se.ErrInvalidRequest.Wrapf("address_hash must be 40 hex characters, got %d", len(m.AddressHash))
	}
	if _, err := hex.DecodeString(m.AddressHash); err != nil {
		return se.ErrInvalidRequest.Wrapf("address_hash is not valid hex: %v", err)
	}
	if len(m.QbtcAddressHash) != 64 {
		return se.ErrInvalidRequest.Wrapf("qbtc_address_hash is required, got %d", len(m.QbtcAddressHash))
	}
	if _, err := hex.DecodeString(m.QbtcAddressHash); err != nil {
		return se.ErrInvalidRequest.Wrapf("qbtc_address_hash is not valid hex: %v", err)
	}
	if len(m.PubKeyHashSha256) != 64 {
		return se.ErrInvalidRequest.Wrapf("pub_key_hash_sha256 must be 64 hex characters, got %d", len(m.PubKeyHashSha256))
	}
	if _, err := hex.DecodeString(m.PubKeyHashSha256); err != nil {
		return se.ErrInvalidRequest.Wrapf("pub_key_hash_sha256 is not valid hex: %v", err)
	}
	return nil
}
