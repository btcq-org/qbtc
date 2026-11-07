package proofservice

import (
	"context"
	"encoding/hex"
	"net/http"

	"github.com/btcq-org/qbtc/x/qbtc/zk"
)

func (s *Service) generateProof(ctx context.Context, req ProveRequest) (*ProveResponse, int, *ErrorResponse) {
	s.logger.Info().Str("claimer_address", req.ClaimerAddress).
		Str("bitcoin_address", req.BitcoinAddress).
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
	if req.Signature == "" {
		return nil, http.StatusBadRequest, &ErrorResponse{
			Error: "signature is required",
			Code:  "INVALID_REQUEST",
		}
	}
	if req.BitcoinAddress == "" {
		return nil, http.StatusBadRequest, &ErrorResponse{
			Error: "bitcoin_address is required",
			Code:  "INVALID_REQUEST",
		}
	}
	if _, err := zk.BitcoinAddressToHash160(req.BitcoinAddress); err != nil {
		return nil, http.StatusBadRequest, &ErrorResponse{
			Error:   "bitcoin_address must be a mainnet P2PKH or P2WPKH address",
			Code:    "INVALID_REQUEST",
			Details: err.Error(),
		}
	}
	if err := zk.CheckBitcoinAddressCanonical(req.BitcoinAddress); err != nil {
		return nil, http.StatusBadRequest, &ErrorResponse{
			Error:   "bitcoin_address must be spelled exactly as stored on the UTXO",
			Code:    "INVALID_REQUEST",
			Details: err.Error(),
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

	// 3. Rebuild the claim message exactly as the chain will.
	chainID := s.cfg.ChainID
	if req.ChainID != "" {
		chainID = req.ChainID
	}
	destination := req.ClaimerAddress
	if req.ReceiverAddress != "" {
		destination = req.ReceiverAddress
	}
	messageText := zk.ClaimMessageText(chainID, req.BitcoinAddress, destination)
	digest := zk.BitcoinSignedMessageDigest(messageText)
	s.logger.Info().Str("message", messageText).Msg("claim message")

	// 4. Recover the signing key (microseconds) before committing to the ~18s
	// in-circuit prove. The recovered key verifies (r, s) by construction, and
	// step 5 ties it to the address, so a signature that fails here can never
	// yield a valid proof.
	pubKey, sigR, sigS, err := zk.ParseBIP137Signature(req.Signature, digest)
	if err != nil {
		return nil, http.StatusBadRequest, &ErrorResponse{
			Error:   "invalid BIP-137 signature",
			Code:    "INVALID_SIGNATURE",
			Details: err.Error(),
		}
	}
	params := zk.ProofParamsFromSignature(pubKey, sigR, sigS, digest)

	// 5. The signing key must own the address being claimed.
	if err := zk.CheckPubKeyOwnsAddress(pubKey, req.BitcoinAddress); err != nil {
		return nil, http.StatusBadRequest, &ErrorResponse{
			Error:   "signature was not made by the key of bitcoin_address",
			Code:    "ADDRESS_MISMATCH",
			Details: err.Error(),
		}
	}
	pubKeyHashSHA256, err := zk.PubKeyHashSHA256(pubKey.SerializeCompressed())
	if err != nil {
		return nil, http.StatusInternalServerError, &ErrorResponse{
			Error:   "failed to compute pubkey SHA256",
			Code:    "PROOF_GENERATION_FAILED",
			Details: err.Error(),
		}
	}

	// 6. Create prover and generate proof
	prover := zk.NewProver(s.cs, s.pk)
	proofBytes, err := prover.GenerateProof(params)
	if err != nil {
		s.logger.Error().Err(err).Msg("proof generation failed")
		return nil, http.StatusInternalServerError, &ErrorResponse{
			Error:   "proof generation failed",
			Code:    "PROOF_GENERATION_FAILED",
			Details: err.Error(),
		}
	}
	s.logger.Info().Msg("generated proof")

	// 7. Build response
	resp := &ProveResponse{
		Proof:            hex.EncodeToString(proofBytes),
		PubKeyHashSHA256: hex.EncodeToString(pubKeyHashSHA256[:]),
		MessageText:      messageText,
		BitcoinAddress:   req.BitcoinAddress,
		UTXOs:            req.UTXOs,
		ClaimerAddress:   req.ClaimerAddress,
		ReceiverAddress:  req.ReceiverAddress,
	}

	// 8. Optionally broadcast the claim to the chain
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
