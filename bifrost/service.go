package bifrost

import (
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/btcq-org/qbtc/bifrost/config"
	"github.com/btcq-org/qbtc/bifrost/keystore"
	"github.com/btcq-org/qbtc/bifrost/metrics"
	"github.com/btcq-org/qbtc/bifrost/p2p"
	"github.com/btcq-org/qbtc/bifrost/qclient"
	"github.com/btcq-org/qbtc/bitcoin"
	"github.com/btcq-org/qbtc/x/qbtc/ebifrost"
	"github.com/btcq-org/qbtc/x/qbtc/types"
	"github.com/cometbft/cometbft/crypto"
	cmtjson "github.com/cometbft/cometbft/libs/json"
	"github.com/cometbft/cometbft/privval"
	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cast"
	"github.com/syndtr/goleveldb/leveldb"
	grpc "google.golang.org/grpc"
)

// Service represents the bifrost service
// it wire up all the components together
type Service struct {
	cfg                 config.Config
	logger              zerolog.Logger
	btcClient           *bitcoin.BtcClient
	pubsub              *p2p.PubSubService
	network             *p2p.Network
	privKey             *keystore.PrivKey
	db                  *leveldb.DB
	stopChan            chan struct{}
	wg                  *sync.WaitGroup
	qclient             qclient.QBTCNode
	ebifrost            ebifrost.LocalhostBifrostClient
	ebifrostConn        *grpc.ClientConn
	validatorPrivateKey crypto.PrivKey

	// http server
	hs *http.Server

	// metrics
	metrics *metrics.Metrics
}

func NewService(cfg config.Config) (*Service, error) {
	_, p, err := net.SplitHostPort(cfg.ListenAddr)
	if err != nil {
		return nil, err
	}
	config := &config.P2PConfig{
		Port:       cast.ToInt(p),
		ExternalIP: cfg.ExternalIP,
	}
	//  client to retrieve node peer addresses

	qbtcGRPCAddress := cfg.QBTCGRPCAddress
	if qbtcGRPCAddress == "" {
		qbtcGRPCAddress = "localhost:9090"
	}
	qClient, err := qclient.New(qbtcGRPCAddress, true)
	if err != nil {
		return nil, fmt.Errorf("fail to created client to qbtc node,err: %w", err)
	}
	// Track if connections should be cleaned up on error
	cleanupQClient := true
	defer func() {
		if cleanupQClient && qClient != nil {
			if closeErr := qClient.Close(); closeErr != nil {
				log.Error().Err(closeErr).Msg("failed to close qclient connection during error cleanup")
			}
		}
	}()

	ebifrostAddress := cfg.EbifrostAddress
	if ebifrostAddress == "" {
		ebifrostAddress = "localhost:50051"
	}
	ebifrostConn, err := qclient.NewGRPCConnection(ebifrostAddress, true)
	if err != nil {
		return nil, fmt.Errorf("failed to create ebifrost client: %w", err)
	}
	// Track if connections should be cleaned up on error
	cleanupEbifrostConn := true
	defer func() {
		if cleanupEbifrostConn && ebifrostConn != nil {
			if closeErr := ebifrostConn.Close(); closeErr != nil {
				log.Error().Err(closeErr).Msg("failed to close ebifrost connection during error cleanup")
			}
		}
	}()

	ebifrostClient := ebifrost.NewLocalhostBifrostClient(ebifrostConn)

	kstore, err := keystore.NewFileKeyStore(cfg.RootPath)
	if err != nil {
		return nil, fmt.Errorf("failed to create file key store,err: %w", err)
	}
	privKey, err := keystore.GetOrCreateKey(kstore, cfg.KeyName)
	if err != nil {
		return nil, fmt.Errorf("failed to get or create p2p key, err: %w", err)
	}
	metrics := metrics.NewMetrics()
	network, err := p2p.NewNetwork(config, qClient, metrics)
	if err != nil {
		return nil, fmt.Errorf("failed to create p2p network, err: %w", err)
	}
	db, err := bitcoin.NewLevelDB(cfg.BitcoinConfig.LocalDBPath, true)
	if err != nil {
		return nil, fmt.Errorf("failed to create level db: %w", err)
	}
	btcClient, err := bitcoin.NewBtcClient(cfg.BitcoinConfig, db)
	if err != nil {
		return nil, fmt.Errorf("failed to create btc client: %w", err)
	}
	validatorPrivateKey, err := getValidatorKey(cfg.QBTCHome)
	if err != nil {
		return nil, fmt.Errorf("failed to get validator private key: %w", err)
	}
	valAddr := sdk.ValAddress(validatorPrivateKey.PubKey().Address())
	log.Info().Str("validator_address", valAddr.String()).Str("validator_pub_key", validatorPrivateKey.PubKey().Address().String()).Msg("loaded validator private key")

	hs := &http.Server{
		Addr:    cfg.HTTPListenAddress,
		Handler: nil,
	}

	// Successfully initialized - don't clean up connections as they're now owned by the service
	cleanupQClient = false
	cleanupEbifrostConn = false

	return &Service{
		cfg:                 cfg,
		network:             network,
		privKey:             privKey,
		db:                  db,
		btcClient:           btcClient,
		logger:              log.With().Str("module", "bifrost_service").Logger(),
		stopChan:            make(chan struct{}),
		wg:                  &sync.WaitGroup{},
		qclient:             qClient,
		ebifrost:            ebifrostClient,
		ebifrostConn:        ebifrostConn,
		validatorPrivateKey: validatorPrivateKey,
		hs:                  hs,
		metrics:             metrics,
	}, nil
}

func getValidatorKey(qbtcHome string) (crypto.PrivKey, error) {
	homeFolder := qbtcHome
	if homeFolder == "" {
		homeDir, err := os.UserHomeDir()
		if err != nil {
			return nil, fmt.Errorf("fail to get validator key,err: %w", err)
		}
		homeFolder = filepath.Join(homeDir, ".qbtc")
	}
	validatorKeyPath := filepath.Join(homeFolder, "config", "priv_validator_key.json")
	_, err := os.Stat(validatorKeyPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("validator key file does not exist at path: %s", validatorKeyPath)
		}
		return nil, fmt.Errorf("error checking validator key file: %w", err)
	}
	fileContent, err := os.ReadFile(validatorKeyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read validator key file: %w", err)
	}
	pvKey := privval.FilePVKey{}
	err = cmtjson.Unmarshal(fileContent, &pvKey)
	if err != nil {
		return nil, fmt.Errorf("error reading PrivValidator key from %v: %w", validatorKeyPath, err)
	}
	return pvKey.PrivKey, nil
}

// Start starts the bifrost service
func (s *Service) Start(ctx context.Context) error {
	if err := s.network.Start(ctx, s.privKey); err != nil {
		return fmt.Errorf("failed to start p2p network: %w", err)
	}
	s.logger.Info().Msg("bifrost service started")
	pubSubService, err := p2p.NewPubSubService(ctx, s.network.GetHost(), s.network.ConnectedPeers(), s.db, s.qclient, s.ebifrost, s.metrics)
	if err != nil {
		return fmt.Errorf("failed to create pubsub service: %w", err)
	}
	s.pubsub = pubSubService
	s.logger.Info().Msg("pubsub service started")
	if err := s.pubsub.Start(); err != nil {
		return fmt.Errorf("failed to start pubsub service: %w", err)
	}
	s.wg.Add(1)
	go s.processBitcoinBlocks(ctx)

	// register routes and metrics
	mux := s.registerRoutes()
	metrics.RegisterHandlers(mux)
	s.hs.Handler = mux
	go func() {
		if err := s.hs.ListenAndServe(); err != nil {
			s.logger.Error().Err(err).Msg("failed to start http server")
		}
	}()
	return nil
}

func (s *Service) processBitcoinBlocks(ctx context.Context) {
	defer s.wg.Done()
	startBlockHeight, err := s.getQBTCLatestProcessBTCBlockHeight(ctx)
	if err != nil {
		s.logger.Error().Err(err).Msg("failed to get latest btc block height")
		startBlockHeight = 0
	}
	var blockHeight int64
	if startBlockHeight > 0 {
		blockHeight = int64(startBlockHeight)
	} else {
		blockHeight, err = s.btcClient.GetStartBlockHeight()
		if err != nil {
			s.logger.Error().Err(err).Msg("failed to get start block height")
			return
		}
		if s.cfg.StartBlockHeight > 0 && blockHeight < s.cfg.StartBlockHeight {
			blockHeight = s.cfg.StartBlockHeight
		}
	}

	s.logger.Info().Int64("start_block_height", blockHeight).Msg("starting to process bitcoin blocks")
	var backOffTime *time.Time
	for {
		select {
		case <-ctx.Done():
			s.logger.Info().Msg("shutting down bitcoin block processing")
			return
		case <-s.stopChan:
			s.logger.Info().Msg("stopping bitcoin block processing")
			return
		default:
			latestBlockHeight, err := s.getQBTCLatestProcessBTCBlockHeight(ctx)
			if err != nil {
				s.logger.Error().Err(err).Msg("failed to get latest bitcoin block height")
			}
			if latestBlockHeight > 0 && uint64(blockHeight) >= latestBlockHeight+10 {
				time.Sleep(5 * time.Second)
				if backOffTime == nil {
					now := time.Now()
					backOffTime = &now
					continue
				} else {
					// if we've been backing off for more than configured minutes, reset to latest block height
					// assume the latest block height +1  btc block didn't reach consensus
					if time.Since(*backOffTime) > time.Duration(s.cfg.BackoffTimeInMinutes)*time.Minute {
						backOffTime = nil
						blockHeight = int64(latestBlockHeight)
						s.logger.Info().Int64("new_block_height", blockHeight).Msg("caught up to latest block height, resetting to latest")
					} else {
						continue
					}
				}
			}
			blockHash, err := s.btcClient.GetBlockHash(blockHeight + 1)
			if err != nil {
				if s.btcClient.ShouldBackoff(err) {
					time.Sleep(time.Second)
				} else {
					s.logger.Error().Err(err).Msgf("failed to get block at height %d", blockHeight+1)
				}
				continue
			}
			s.logger.Info().Str("block_hash", blockHash).Int64("block_height", blockHeight+1).Msg("retrieved latest block hash")

			if err := s.getBtcBlock(blockHeight); err != nil {
				// when there is an error , let's retry it
				s.logger.Error().Err(err).Msgf("failed to get btc block at height %d", blockHeight)
				continue
			}
			if err := s.btcClient.SetStartBlockHeight(blockHeight); err != nil {
				s.logger.Error().Err(err).Msgf("failed to set start block height %d", blockHeight)
			}

			blockHeight++
		}
	}
}

func (s *Service) getQBTCLatestProcessBTCBlockHeight(ctx context.Context) (uint64, error) {
	newCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	return s.qclient.GetLatestBtcBlockHeight(newCtx)
}

// getBtcBlock retrieves the bitcoin block at the given height
func (s *Service) getBtcBlock(height int64) error {
	blockHash, err := s.btcClient.GetBlockHash(height)
	if err != nil {
		return fmt.Errorf("failed to get block hash at height %d: %w", height, err)
	}
	block, err := s.btcClient.GetBlockVerboseTxs(blockHash)
	if err != nil {
		return fmt.Errorf("failed to get block verbose txs at height %d: %w", height, err)
	}
	if block == nil {
		return nil
	}
	s.logger.Info().Int64("block_height", height).Msg("published block gossip")
	content, err := json.Marshal(block)
	if err != nil {
		return fmt.Errorf("failed to marshal block content at height %d: %w", height, err)
	}
	compressedContent, err := types.GzipDeterministic(content, gzip.BestCompression)
	if err != nil {
		return fmt.Errorf("failed to compress block content at height %d: %w", height, err)
	}
	sig, err := s.validatorPrivateKey.Sign(compressedContent)
	if err != nil {
		return fmt.Errorf("failed to sign block content at height %d: %w", height, err)
	}
	// use consensus address to explicitly identify the consensus address of the validator
	// sdk.ValAddress is reserved for the OperatorAddress
	// eg: qbtcvalcons1...
	valAddr := sdk.ConsAddress(s.validatorPrivateKey.PubKey().Address())
	blockGassip := types.BlockGossip{
		Hash:         block.Hash,
		Height:       uint64(block.Height),
		BlockContent: compressedContent,
		Attestation: &types.Attestation{
			Address:   valAddr.String(),
			Signature: sig,
		},
	}
	err = s.pubsub.Publish(blockGassip)
	if err != nil {
		return fmt.Errorf("failed to publish block gossip at height %d: %w", height, err)
	}
	s.metrics.IncrCounter(metrics.MetricNameProcessedBlocks)
	return nil
}

// Stop stops the bifrost service
func (s *Service) Stop() {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := s.hs.Shutdown(ctx); err != nil {
		s.logger.Error().Err(err).Msg("failed to shutdown http server")
	} else {
		s.logger.Info().Msg("http server shutdown")
	}
	select {
	case <-s.stopChan:
	default:
		close(s.stopChan)
	}
	s.wg.Wait()
	if s.pubsub != nil {
		if err := s.pubsub.Stop(); err != nil {
			s.logger.Error().Err(err).Msg("failed to stop pubsub service")
		} else {
			s.logger.Info().Msg("pubsub service stopped")
		}
	}
	if err := s.network.Stop(); err != nil {
		s.logger.Error().Err(err).Msg("failed to stop p2p network")
	} else {
		s.logger.Info().Msg("p2p network stopped")
	}
	if err := s.btcClient.Close(); err != nil {
		s.logger.Error().Err(err).Msg("failed to close btc client")
	} else {
		s.logger.Info().Msg("btc client closed")
	}
	if err := s.ebifrostConn.Close(); err != nil {
		s.logger.Error().Err(err).Msg("failed to close ebifrost connection")
	} else {
		s.logger.Info().Msg("ebifrost connection closed")
	}
	if err := s.db.Close(); err != nil {
		s.logger.Error().Err(err).Msg("failed to close leveldb")
	} else {
		s.logger.Info().Msg("leveldb closed")
	}
}
