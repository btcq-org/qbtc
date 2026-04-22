package proofservice

import (
	"encoding/hex"
	"math/big"
	"net/http"

	"github.com/btcq-org/qbtc/x/qbtc/zk"
	"github.com/btcsuite/btcd/btcec/v2"
)

func (s *Service) generateProof(req ProveRequest) (*ProveResponse, int, *ErrorResponse) {
	s.logger.Info().Str("claimer_address", req.ClaimerAddress).
		Int("num_utxos", len(req.UTXOs)).
		Msg("received proof generation request")
	// 1. Validate required fields
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

	// 9. Create prover and generate proof
	prover := zk.NewProver(s.cs, s.pk)

	proofBytes, err := prover.GenerateProof(zk.ProofParams{
		SignatureR:      sigR,
		SignatureS:      sigS,
		PublicKeyX:      pubKey.X(),
		PublicKeyY:      pubKey.Y(),
		MessageHash:     messageHash,
		AddressHash:     addressHash,
		QBTCAddressHash: qbtcAddressHash,
		ChainID:         chainIDHash,
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
	return &ProveResponse{
		Proof:            hex.EncodeToString(proofBytes),
		MessageHash:      hex.EncodeToString(messageHash[:]),
		AddressHash:      hex.EncodeToString(addressHash[:]),
		PubKeyHashSHA256: hex.EncodeToString(pubKeyHashSHA256[:]),
		QBTCAddressHash:  hex.EncodeToString(qbtcAddressHash[:]),
		UTXOs:            req.UTXOs,
		ClaimerAddress:   req.ClaimerAddress,
	}, http.StatusOK, nil
}
