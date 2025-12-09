package bifrost

import (
	"encoding/json"
	"net/http"
)

func (s *Service) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("OK"))
}

func (s *Service) handleConnectedPeers(w http.ResponseWriter, r *http.Request) {
	peers := s.network.ConnectedPeers()
	json.NewEncoder(w).Encode(peers)
}

func (s *Service) registerRoutes() {
	http.HandleFunc("/health", s.handleHealth)
	http.HandleFunc("/connected-peers", s.handleConnectedPeers)
}
