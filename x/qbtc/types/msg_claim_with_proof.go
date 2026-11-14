package types

import (
	"encoding/hex"
	"fmt"

	sdk "github.com/cosmos/cosmos-sdk/types"
	se "github.com/cosmos/cosmos-sdk/types/errors"

	"github.com/btcq-org/qbtc/common"
	"github.com/btcq-org/qbtc/x/qbtc/zk"
)

// Hash160Length is the length of a Bitcoin Hash160 (RIPEMD160(SHA256(pubkey))).
const Hash160Length = 20

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

	// Validate optional receiver address when provided
	if m.Receiver != "" {
		if _, err := sdk.AccAddressFromBech32(m.Receiver); err != nil {
			return se.ErrInvalidAddress.Wrapf("invalid receiver address: %v", err)
		}
	}

	if err := ValidateReferrer(m.Referrer, m.Destination()); err != nil {
		return err
	}

	// Validate broadcaster (the cosmos tx signer)
	if m.Broadcaster == "" {
		return se.ErrInvalidRequest.Wrap("broadcaster address is required")
	}
	if _, err := sdk.AccAddressFromBech32(m.Broadcaster); err != nil {
		return se.ErrInvalidAddress.Wrapf("invalid broadcaster address: %v", err)
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
	if len(m.Proof) == 0 {
		return se.ErrInvalidRequest.Wrap("proof data is required")
	}
	if want := hex.EncodedLen(zk.ProofSize(zk.ClaimCircuitNbCommitments)); len(m.Proof) != want {
		return se.ErrInvalidRequest.Wrapf("proof data is %d hex characters, want %d", len(m.Proof), want)
	}
	proofBytes, err := hex.DecodeString(m.Proof)
	if err != nil {
		return se.ErrInvalidRequest.Wrapf("proof data is not valid hex: %v", err)
	}
	// The layout check stops CheckTx from passing a proof whose length
	// prefixes would make deserialization allocate unbounded memory.
	if err := zk.CheckProofLayout(proofBytes, zk.ClaimCircuitNbCommitments); err != nil {
		return se.ErrInvalidRequest.Wrapf("malformed proof: %v", err)
	}

	if len(m.PubKeyHashSha256) != 64 {
		return se.ErrInvalidRequest.Wrapf("pub_key_hash_sha256 must be 64 hex characters, got %d", len(m.PubKeyHashSha256))
	}
	if _, err := hex.DecodeString(m.PubKeyHashSha256); err != nil {
		return se.ErrInvalidRequest.Wrapf("pub_key_hash_sha256 is not valid hex: %v", err)
	}
	return nil
}

// Destination returns the address the claimed coins go to and the signed claim
// message names: the receiver when set, otherwise the claimer.
func (m *MsgClaimWithProof) Destination() string {
	if m.Receiver != "" {
		return m.Receiver
	}
	return m.Claimer
}

// ValidateReferrer checks the optional referrer of a claim sent to
// destination. An empty referrer is valid. Otherwise it must be a qbtc address
// spelled exactly as the bech32 encoder writes it: the signed claim message
// covers the string and referral totals are kept per account, so two
// spellings of one account must not both verify. A claim cannot refer itself.
// Wallet tooling calls this before asking the user to sign.
func ValidateReferrer(referrer, destination string) error {
	if referrer == "" {
		return nil
	}
	referrerBytes, err := sdk.GetFromBech32(referrer, common.AccountAddressPrefix)
	if err != nil {
		return se.ErrInvalidAddress.Wrapf("invalid referrer address: %v", err)
	}
	if err := sdk.VerifyAddressFormat(referrerBytes); err != nil {
		return se.ErrInvalidAddress.Wrapf("invalid referrer address: %v", err)
	}
	canonical, err := sdk.Bech32ifyAddressBytes(common.AccountAddressPrefix, referrerBytes)
	if err != nil {
		return se.ErrInvalidAddress.Wrapf("invalid referrer address: %v", err)
	}
	if canonical != referrer {
		return se.ErrInvalidAddress.Wrapf("referrer address must be canonical bech32 %s", canonical)
	}
	destinationBytes, err := sdk.GetFromBech32(destination, common.AccountAddressPrefix)
	if err != nil {
		return se.ErrInvalidAddress.Wrapf("invalid destination address: %v", err)
	}
	if sdk.AccAddress(referrerBytes).Equals(sdk.AccAddress(destinationBytes)) {
		return se.ErrInvalidRequest.Wrap("referrer cannot be the claim destination")
	}
	return nil
}
