package proofservice

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/btcq-org/qbtc/proof-service/config"
	"github.com/btcq-org/qbtc/proof-service/metrics"
	"github.com/btcq-org/qbtc/x/qbtc/zk"
	"github.com/consensys/gnark/backend/plonk"
	"github.com/consensys/gnark/constraint"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

// Service represents the proof-service.
type Service struct {
	cfg    config.Config
	logger zerolog.Logger

	// ZK proving components (loaded once at startup)
	cs constraint.ConstraintSystem
	pk plonk.ProvingKey

	// Chain ID hash (precomputed at startup)
	chainIDHash [8]byte

	// Optional on-chain broadcaster (nil when not configured)
	broadcaster *Broadcaster

	// HTTP server
	hs *http.Server

	// Metrics
	metrics *metrics.Metrics

	// Shutdown coordination
	stopChan chan struct{}
	wg       *sync.WaitGroup
}

// NewService creates a new proof-service instance.
func NewService(cfg config.Config) (*Service, error) {
	logger := log.With().Str("module", "proof_service").Logger()

	// Load constraint system
	csPath := filepath.Join(cfg.SetupDir, "circuit.cs")
	csBytes, err := os.ReadFile(csPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read constraint system from %s: %w", csPath, err)
	}
	cs, err := zk.DeserializeConstraintSystem(csBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to deserialize constraint system: %w", err)
	}
	logger.Info().Str("path", csPath).Msg("loaded constraint system")

	// Load proving key
	pkPath := filepath.Join(cfg.SetupDir, "proving.key")
	pkBytes, err := os.ReadFile(pkPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read proving key from %s: %w", pkPath, err)
	}
	pk, err := zk.DeserializeProvingKey(pkBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to deserialize proving key: %w", err)
	}
	logger.Info().Str("path", pkPath).Msg("loaded proving key")

	// Precompute chain ID hash
	chainIDHash := zk.ComputeChainIDHash(cfg.ChainID)
	logger.Info().Str("chain_id", cfg.ChainID).Msg("computed chain ID hash")

	// Optionally create broadcaster
	broadcaster, err := NewBroadcaster(cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize broadcaster: %w", err)
	}
	if broadcaster != nil {
		logger.Info().Str("from_addr", broadcaster.FromAddress()).Str("grpc_addr", cfg.BroadcastGRPCAddr).Msg("broadcaster enabled")
	}

	// Create metrics
	m := metrics.NewMetrics()

	// Create HTTP server (handler set in Start)
	hs := &http.Server{
		Addr:         cfg.HTTPListenAddr,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: time.Duration(cfg.RequestTimeoutSec+10) * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	return &Service{
		cfg:         cfg,
		logger:      logger,
		cs:          cs,
		pk:          pk,
		chainIDHash: chainIDHash,
		broadcaster: broadcaster,
		hs:          hs,
		metrics:     m,
		stopChan:    make(chan struct{}),
		wg:          &sync.WaitGroup{},
	}, nil
}

// Start starts the HTTP server.
func (s *Service) Start(ctx context.Context) error {
	// Register routes
	mux := s.registerRoutes()
	metrics.RegisterHandlers(mux)
	s.hs.Handler = mux

	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		s.logger.Info().Str("addr", s.cfg.HTTPListenAddr).Msg("starting HTTP server")
		if err := s.hs.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			s.logger.Error().Err(err).Msg("HTTP server error")
		}
	}()

	return nil
}

// Stop gracefully shuts down the service.
func (s *Service) Stop() {
	s.logger.Info().Msg("shutting down proof-service...")

	// Signal stop
	select {
	case <-s.stopChan:
	default:
		close(s.stopChan)
	}

	// Shutdown HTTP server with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := s.hs.Shutdown(ctx); err != nil {
		s.logger.Error().Err(err).Msg("failed to shutdown HTTP server gracefully")
	} else {
		s.logger.Info().Msg("HTTP server shutdown complete")
	}

	s.wg.Wait()

	if s.broadcaster != nil {
		s.broadcaster.Close()
	}

	s.logger.Info().Msg("proof-service stopped")
}
