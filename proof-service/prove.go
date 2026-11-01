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
	walletForm := req.Signature != ""
	tssForm := req.SignatureR != "" || req.SignatureS != "" || req.PublicKey != ""
	if walletForm == tssForm {
		return nil, http.StatusBadRequest, &ErrorResponse{
			Error: "exactly one of signature (BIP-137 base64) or signature_r+signature_s+public_key is required",
			Code:  "INVALID_REQUEST",
		}
	}
	if tssForm && (req.SignatureR == "" || req.SignatureS == "" || req.PublicKey == "") {
		return nil, http.StatusBadRequest, &ErrorResponse{
			Error: "signature_r, signature_s and public_key are all required",
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

	// 4. Obtain (pubkey, r, s) from whichever signature form was given, and
	// verify it natively (microseconds) before committing to the ~18s
	// in-circuit prove. The circuit proves this exact relation, so a signature
	// that does not verify here can never yield a valid proof.
	var (
		pubKey *btcec.PublicKey
		params zk.ProofParams
	)
	if walletForm {
		pub, r, sScalar, err := zk.ParseBIP137Signature(req.Signature, digest)
		if err != nil {
			return nil, http.StatusBadRequest, &ErrorResponse{
				Error:   "invalid BIP-137 signature",
				Code:    "INVALID_SIGNATURE",
				Details: err.Error(),
			}
		}
		pubKey = pub
		params = zk.ProofParamsFromSignature(pub, r, sScalar, digest)
	} else {
		var errResp *ErrorResponse
		pubKey, params, errResp = s.paramsFromRawSignature(req, digest)
		if errResp != nil {
			return nil, http.StatusBadRequest, errResp
		}
	}

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

// paramsFromRawSignature handles the TSS form: hex r, s and compressed pubkey
// over the claim digest.
func (s *Service) paramsFromRawSignature(req ProveRequest, digest [32]byte) (*btcec.PublicKey, zk.ProofParams, *ErrorResponse) {
	sigRBytes, err := hex.DecodeString(req.SignatureR)
	if err != nil || len(sigRBytes) != 32 {
		return nil, zk.ProofParams{}, &ErrorResponse{
			Error: "signature_r must be 64 hex characters (32 bytes)",
			Code:  "INVALID_SIGNATURE",
		}
	}
	sigSBytes, err := hex.DecodeString(req.SignatureS)
	if err != nil || len(sigSBytes) != 32 {
		return nil, zk.ProofParams{}, &ErrorResponse{
			Error: "signature_s must be 64 hex characters (32 bytes)",
			Code:  "INVALID_SIGNATURE",
		}
	}
	pubKeyBytes, err := hex.DecodeString(req.PublicKey)
	if err != nil || len(pubKeyBytes) != 33 {
		return nil, zk.ProofParams{}, &ErrorResponse{
			Error: "public_key must be 66 hex characters (33 bytes compressed)",
			Code:  "INVALID_PUBLIC_KEY",
		}
	}
	pubKey, err := btcec.ParsePubKey(pubKeyBytes)
	if err != nil {
		return nil, zk.ProofParams{}, &ErrorResponse{
			Error:   "invalid compressed public key",
			Code:    "INVALID_PUBLIC_KEY",
			Details: err.Error(),
		}
	}
	if err := verifyECDSASignature(pubKey, digest[:], sigRBytes, sigSBytes); err != nil {
		return nil, zk.ProofParams{}, &ErrorResponse{
			Error:   "signature does not verify against the public key and claim message",
			Code:    "INVALID_SIGNATURE",
			Details: err.Error(),
		}
	}
	return pubKey, zk.ProofParamsFromSignature(pubKey, new(big.Int).SetBytes(sigRBytes), new(big.Int).SetBytes(sigSBytes), digest), nil
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
