package bifrost

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
)

func (s *Service) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain")
	w.WriteHeader(http.StatusOK)
	if _, err := w.Write([]byte("OK")); err != nil {
		s.logger.Error().Err(err).Msg("failed to write health response")
	}
}

func (s *Service) handleConnectedPeers(w http.ResponseWriter, r *http.Request) {
	peers := s.network.ConnectedPeers()
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(peers); err != nil {
		s.logger.Error().Err(err).Msg("failed to encode connected peers")
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
	}
}

func (s *Service) handlePeerId(w http.ResponseWriter, r *http.Request) {
	peerID := s.network.GetHost().ID()
	_, p, err := net.SplitHostPort(s.cfg.ListenAddr)
	if err != nil {
		s.logger.Error().Err(err).Msg("failed to parse listen address")
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	externalIP := s.cfg.ExternalIP
	if externalIP == "" {
		externalIP = "0.0.0.0"
	}
	resp := fmt.Sprintf("%s@%s:%s", peerID.String(), externalIP, p)
	w.Header().Set("Content-Type", "text/plain")
	w.WriteHeader(http.StatusOK)
	if _, err := w.Write([]byte(resp)); err != nil {
		s.logger.Error().Err(err).Msg("failed to write peer id response")
	}
}

func (s *Service) registerRoutes() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("/health", s.handleHealth)
	mux.HandleFunc("/connected-peers", s.handleConnectedPeers)
	mux.HandleFunc("/peerid", s.handlePeerId)
	return mux
}
