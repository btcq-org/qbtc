package bifrost

import (
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/btcq-org/qbtc/bifrost/config"
	"github.com/btcq-org/qbtc/bifrost/keystore"
	"github.com/btcq-org/qbtc/bifrost/p2p"
	"github.com/btcq-org/qbtc/bifrost/qclient"
	"github.com/btcq-org/qbtc/bitcoin"
	"github.com/btcq-org/qbtc/x/qbtc/types"
	"github.com/cometbft/cometbft/crypto"
	cmtjson "github.com/cometbft/cometbft/libs/json"
	"github.com/cometbft/cometbft/privval"
	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cast"
	"github.com/syndtr/goleveldb/leveldb"
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
	validatorPrivateKey crypto.PrivKey
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
	qClient, err := qclient.New(fmt.Sprintf("localhost:%d", 9090), true)
	if err != nil {
		return nil, fmt.Errorf("fail to created client to qbtc node,err: %w", err)
	}

	kstore, err := keystore.NewFileKeyStore(cfg.RootPath)
	if err != nil {
		return nil, fmt.Errorf("failed to create file key store,err: %w", err)
	}
	privKey, err := keystore.GetOrCreateKey(kstore, cfg.KeyName)
	if err != nil {
		return nil, fmt.Errorf("failed to get or create p2p key, err: %w", err)
	}

	network, err := p2p.NewNetwork(config, qClient)
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
	log.Info().Str("validator_address", valAddr.String()).Msg("loaded validator private key")
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
		validatorPrivateKey: validatorPrivateKey,
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
	pubSubService, err := p2p.NewPubSubService(ctx, s.network.GetHost(), nil, s.db)
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
	return nil
}

func (s *Service) processBitcoinBlocks(ctx context.Context) {
	defer s.wg.Done()
	blockHeight, err := s.btcClient.GetStartBlockHeight()
	if err != nil {
		s.logger.Error().Err(err).Msg("failed to get start block height")
		return
	}

	if s.cfg.StartBlockHeight > 0 && blockHeight < s.cfg.StartBlockHeight {
		blockHeight = s.cfg.StartBlockHeight
	}
	s.logger.Info().Int64("start_block_height", blockHeight).Msg("starting to process bitcoin blocks")

	for {
		select {
		case <-ctx.Done():
			s.logger.Info().Msg("shutting down bitcoin block processing")
			return
		case <-s.stopChan:
			s.logger.Info().Msg("stopping bitcoin block processing")
			return
		default:
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
	// TODO: sign and publish the block gossip message
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
	s.logger.Info().Msgf("signature length for block at height %d: %d", height, len(sig))
	valAddr := sdk.ValAddress(s.validatorPrivateKey.PubKey().Address())
	blockGassip := types.BlockGossip{
		Hash:         block.Hash,
		Height:       uint64(block.Height),
		BlockContent: compressedContent,
		Attestation: &types.Attestation{
			Address:   valAddr.String(),
			Signature: sig,
		},
	}
	return s.pubsub.Publish(blockGassip)
}

// Stop stops the bifrost service
func (s *Service) Stop() {
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
	if err := s.db.Close(); err != nil {
		s.logger.Error().Err(err).Msg("failed to close leveldb")
	} else {
		s.logger.Info().Msg("leveldb closed")
	}
}
