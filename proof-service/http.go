package proofservice

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/btcq-org/qbtc/proof-service/metrics"
	"github.com/btcq-org/qbtc/x/qbtc/types"
)

// ProveRequest is the JSON request body for POST /prove.
type ProveRequest struct {
	// SignatureR is the raw ECDSA signature R value (64 hex chars, 32 bytes).
	SignatureR string `json:"signature_r"`

	// SignatureS is the raw ECDSA signature S value (64 hex chars, 32 bytes).
	SignatureS string `json:"signature_s"`

	// PublicKey is the compressed public key (66 hex chars, 33 bytes).
	PublicKey string `json:"public_key"`

	// UTXOs are the UTXOs to claim.
	UTXOs []types.UTXORef `json:"utxos"`

	// ClaimerAddress is the QBTC claimer address.
	ClaimerAddress string `json:"claimer_address"`

	// ChainID for message binding (e.g., "qbtc-1").
	// If empty, uses the configured default.
	ChainID string `json:"chain_id,omitempty"`

	// Broadcast, if true, submits the resulting MsgClaimWithProof to the chain
	// after proof generation. Requires broadcast_grpc_addr and broadcast_priv_key_hex
	// to be configured in the service config.
	Broadcast bool `json:"broadcast,omitempty"`
}

// ProveResponse is the JSON response for POST /prove.
// All fields are ready for use in MsgClaimWithProof.
type ProveResponse struct {
	// Proof is the hex-encoded PLONK proof.
	Proof string `json:"proof"`

	// MessageHash is the hex-encoded message hash (64 chars, 32 bytes).
	MessageHash string `json:"message_hash"`

	// AddressHash is the hex-encoded Bitcoin address hash - Hash160 (40 chars, 20 bytes).
	AddressHash string `json:"address_hash"`

	// PubKeyHashSHA256 is the hex-encoded SHA256 of the SEC-compressed pubkey
	// (64 chars, 32 bytes). The chain's verifier natively applies RIPEMD160 to
	// it to recover AddressHash, so MsgClaimWithProof must carry this value.
	PubKeyHashSHA256 string `json:"pub_key_hash_sha256"`

	// QBTCAddressHash is the hex-encoded QBTC address hash (64 chars, 32 bytes).
	QBTCAddressHash string `json:"qbtc_address_hash"`

	// UTXOs are the UTXOs included in the request (echoed back).
	UTXOs []types.UTXORef `json:"utxos"`

	// ClaimerAddress is the claimer address (echoed back).
	ClaimerAddress string `json:"claimer_address"`

	// TxHash is the on-chain transaction hash, populated only when broadcast=true.
	TxHash string `json:"tx_hash,omitempty"`
}

// ErrorResponse is returned for error cases.
type ErrorResponse struct {
	Error   string `json:"error"`
	Code    string `json:"code,omitempty"`
	Details string `json:"details,omitempty"`
}

// HealthResponse is returned by GET /health.
type HealthResponse struct {
	Status      string `json:"status"`
	SetupLoaded bool   `json:"setup_loaded"`
}

// buildHandler assembles the routed mux and wraps it in the middleware chain.
// The /prove path gets the protective controls (body cap, auth, concurrency
// bound); /health and /metrics stay cheap and unauthenticated so probes and
// scrapers keep working. recover + access logging wrap everything.
func (s *Service) buildHandler() http.Handler {
	mux := http.NewServeMux()

	// Protective controls for the expensive /prove path, ordered so a proving
	// slot is only ever held by an authorized request.
	proveMW := make([]middleware, 0, 3)
	if s.cfg.MaxRequestBytes > 0 {
		proveMW = append(proveMW, maxBytesMiddleware(s.cfg.MaxRequestBytes, s.metrics))
	}
	if s.cfg.AuthToken != "" {
		proveMW = append(proveMW, authMiddleware(s.cfg.AuthToken, s.metrics))
	}
	if s.provingSem != nil {
		proveMW = append(proveMW, concurrencyMiddleware(s.provingSem, s.metrics))
	}
	mux.Handle("/prove", chain(http.HandlerFunc(s.handleProve), proveMW...))
	mux.HandleFunc("/health", s.handleHealth)
	metrics.RegisterHandlers(mux)

	return chain(mux, recoverMiddleware(s.logger), requestLogMiddleware(s.logger))
}

func (s *Service) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	resp := HealthResponse{
		Status:      "healthy",
		SetupLoaded: s.cs != nil && s.pk != nil,
	}

	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		s.logger.Error().Err(err).Msg("failed to encode health response")
	}
}

func (s *Service) handleProve(w http.ResponseWriter, r *http.Request) {
	startTime := time.Now()

	// Only accept POST
	if r.Method != http.MethodPost {
		s.writeError(w, http.StatusMethodNotAllowed, "INVALID_REQUEST", "only POST method allowed", "")
		return
	}

	// Parse request
	var req ProveRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeError(w, http.StatusBadRequest, "INVALID_REQUEST", "invalid JSON body", err.Error())
		return
	}

	// Validate and generate proof
	resp, httpCode, errResp := s.generateProof(r.Context(), req)
	if errResp != nil {
		s.metrics.IncrCounter(metrics.MetricProofsFailed)
		s.writeErrorStruct(w, httpCode, errResp)
		return
	}

	// Success
	s.metrics.IncrCounter(metrics.MetricProofsGenerated)
	s.metrics.ObserveHistogram(metrics.MetricProofDuration, time.Since(startTime).Seconds())

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	s.logger.Info().Str("claimer_address", req.ClaimerAddress).Msg("successfully generated proof")
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		s.logger.Error().Err(err).Msg("failed to encode prove response")
	}
}

func (s *Service) writeError(w http.ResponseWriter, status int, code, msg, details string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(ErrorResponse{
		Error:   msg,
		Code:    code,
		Details: details,
	}); err != nil {
		s.logger.Error().Err(err).Msg("failed to encode error response")
	}
}

func (s *Service) writeErrorStruct(w http.ResponseWriter, status int, resp *ErrorResponse) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		s.logger.Error().Err(err).Msg("failed to encode error response")
	}
}
