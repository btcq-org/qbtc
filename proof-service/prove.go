package proofservice

import (
	"context"
	"encoding/hex"
	"errors"
	"math/big"
	"net/http"

	"github.com/btcq-org/qbtc/x/qbtc/zk"
	"github.com/btcsuite/btcd/btcec/v2"
	btcecdsa "github.com/btcsuite/btcd/btcec/v2/ecdsa"
)

func (s *Service) generateProof(ctx context.Context, req ProveRequest) (*ProveResponse, int, *ErrorResponse) {
	s.logger.Info().Str("claimer_address", req.ClaimerAddress).
		Int("num_utxos", len(req.UTXOs)).
		Msg("received proof generation request")

	// 1. Fail-fast broadcast pre-checks before doing any ZK work.
	if req.Broadcast {
		if s.broadcaster == nil {
			return nil, http.StatusBadRequest, &ErrorResponse{
				Error: "broadcasting is not configured on this service",
				Code:  "BROADCAST_NOT_CONFIGURED",
			}
		}
		if req.ChainID != "" && req.ChainID != s.cfg.ChainID {
			return nil, http.StatusBadRequest, &ErrorResponse{
				Error: "chain_id must match the service chain when broadcast=true",
				Code:  "CHAIN_ID_MISMATCH",
			}
		}
	}

	// 2. Validate required fields
	if req.SignatureR == "" || req.SignatureS == "" {
		return nil, http.StatusBadRequest, &ErrorResponse{
			Error: "signature_r and signature_s are required",
			Code:  "INVALID_REQUEST",
		}
	}
	if req.PublicKey == "" {
		return nil, http.StatusBadRequest, &ErrorResponse{
			Error: "public_key is required",
			Code:  "INVALID_REQUEST",
		}
	}
	if req.ClaimerAddress == "" {
		return nil, http.StatusBadRequest, &ErrorResponse{
			Error: "claimer_address is required",
			Code:  "INVALID_REQUEST",
		}
	}
	if len(req.UTXOs) == 0 {
		return nil, http.StatusBadRequest, &ErrorResponse{
			Error: "at least one UTXO is required",
			Code:  "INVALID_REQUEST",
		}
	}

	// 2. Parse signature R (must be 32 bytes)
	sigRBytes, err := hex.DecodeString(req.SignatureR)
	if err != nil || len(sigRBytes) != 32 {
		return nil, http.StatusBadRequest, &ErrorResponse{
			Error: "signature_r must be 64 hex characters (32 bytes)",
			Code:  "INVALID_SIGNATURE",
		}
	}
	sigR := new(big.Int).SetBytes(sigRBytes)

	// 3. Parse signature S (must be 32 bytes)
	sigSBytes, err := hex.DecodeString(req.SignatureS)
	if err != nil || len(sigSBytes) != 32 {
		return nil, http.StatusBadRequest, &ErrorResponse{
			Error: "signature_s must be 64 hex characters (32 bytes)",
			Code:  "INVALID_SIGNATURE",
		}
	}
	sigS := new(big.Int).SetBytes(sigSBytes)

	// 4. Parse and validate public key (33 bytes compressed)
	pubKeyBytes, err := hex.DecodeString(req.PublicKey)
	if err != nil || len(pubKeyBytes) != 33 {
		return nil, http.StatusBadRequest, &ErrorResponse{
			Error: "public_key must be 66 hex characters (33 bytes compressed)",
			Code:  "INVALID_PUBLIC_KEY",
		}
	}
	pubKey, err := btcec.ParsePubKey(pubKeyBytes)
	if err != nil {
		return nil, http.StatusBadRequest, &ErrorResponse{
			Error:   "invalid compressed public key",
			Code:    "INVALID_PUBLIC_KEY",
			Details: err.Error(),
		}
	}

	// 5. Compute address hash (Hash160 of compressed pubkey) and its SHA256
	// intermediate. Both are part of the response so the claimer can build a
	// MsgClaimWithProof whose pub_key_hash_sha256 matches the proof's public
	// input.
	addressHash, err := zk.PublicKeyToAddressHash(pubKeyBytes)
	if err != nil {
		return nil, http.StatusInternalServerError, &ErrorResponse{
			Error:   "failed to compute address hash",
			Code:    "PROOF_GENERATION_FAILED",
			Details: err.Error(),
		}
	}
	pubKeyHashSHA256, err := zk.PubKeyHashSHA256(pubKeyBytes)
	if err != nil {
		return nil, http.StatusInternalServerError, &ErrorResponse{
			Error:   "failed to compute pubkey SHA256",
			Code:    "PROOF_GENERATION_FAILED",
			Details: err.Error(),
		}
	}

	// 6. Compute QBTC address hash
	qbtcAddressHash := zk.HashQBTCAddress(req.ClaimerAddress)

	// 7. Determine chain ID hash (use request or default)
	chainIDHash := s.chainIDHash
	if req.ChainID != "" {
		chainIDHash = zk.ComputeChainIDHash(req.ChainID)
	}

	// 8. Compute message hash
	messageHash := zk.ComputeClaimMessage(addressHash, qbtcAddressHash, chainIDHash)
	s.logger.Info().Str("message_hash", hex.EncodeToString(messageHash[:])).Msg("computed message hash")

	// 8b. Fail fast: verify the ECDSA signature natively (microseconds) before
	// committing to the ~18s in-circuit prove. The circuit proves this exact
	// relation, so a signature that does not verify here can never yield a
	// valid proof; rejecting it now avoids wasting proving capacity.
	if err := verifyECDSASignature(pubKey, messageHash[:], sigRBytes, sigSBytes); err != nil {
		return nil, http.StatusBadRequest, &ErrorResponse{
			Error:   "signature does not verify against the public key and claim message",
			Code:    "INVALID_SIGNATURE",
			Details: err.Error(),
		}
	}

	// 9. Create prover and generate proof
	prover := zk.NewProver(s.cs, s.pk)

	proofBytes, err := prover.GenerateProof(zk.ProofParams{
		SignatureR:  sigR,
		SignatureS:  sigS,
		PublicKeyX:  pubKey.X(),
		PublicKeyY:  pubKey.Y(),
		MessageHash: messageHash,
	})
	s.logger.Info().Msg("generated proof")
	if err != nil {
		s.logger.Error().Err(err).Msg("proof generation failed")
		return nil, http.StatusInternalServerError, &ErrorResponse{
			Error:   "proof generation failed",
			Code:    "PROOF_GENERATION_FAILED",
			Details: err.Error(),
		}
	}

	// 10. Build response
	resp := &ProveResponse{
		Proof:            hex.EncodeToString(proofBytes),
		MessageHash:      hex.EncodeToString(messageHash[:]),
		AddressHash:      hex.EncodeToString(addressHash[:]),
		PubKeyHashSHA256: hex.EncodeToString(pubKeyHashSHA256[:]),
		QBTCAddressHash:  hex.EncodeToString(qbtcAddressHash[:]),
		UTXOs:            req.UTXOs,
		ClaimerAddress:   req.ClaimerAddress,
	}

	// 11. Optionally broadcast the claim to the chain
	if req.Broadcast {
		txHash, err := s.broadcaster.BroadcastClaim(ctx, resp)
		if err != nil {
			s.logger.Error().Err(err).Msg("broadcast failed")
			return nil, http.StatusInternalServerError, &ErrorResponse{
				Error:   "broadcast failed",
				Code:    "BROADCAST_FAILED",
				Details: err.Error(),
			}
		}
		resp.TxHash = txHash
		s.logger.Info().Str("tx_hash", txHash).Msg("broadcast claim tx")
	}

	return resp, http.StatusOK, nil
}

// verifyECDSASignature checks that (r, s) is a valid secp256k1 ECDSA signature
// of hash under pubKey. rBytes and sBytes must each be 32 bytes. It enforces
// that r and s are in the valid range [1, n-1] and performs the full native
// verification, matching what the circuit proves in-circuit.
func verifyECDSASignature(pubKey *btcec.PublicKey, hash, rBytes, sBytes []byte) error {
	var r, s btcec.ModNScalar
	if r.SetByteSlice(rBytes) {
		return errors.New("signature_r is not less than the curve order")
	}
	if s.SetByteSlice(sBytes) {
		return errors.New("signature_s is not less than the curve order")
	}
	if r.IsZero() {
		return errors.New("signature_r must be non-zero")
	}
	if s.IsZero() {
		return errors.New("signature_s must be non-zero")
	}
	if !btcecdsa.NewSignature(&r, &s).Verify(hash, pubKey) {
		return errors.New("signature verification failed")
	}
	return nil
}
