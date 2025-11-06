package bitcoin

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/btcsuite/btcd/btcjson"
	"github.com/ethereum/go-ethereum/rpc"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/spf13/viper"
	"github.com/syndtr/goleveldb/leveldb"
)

func GetConfig() (*Config, error) {
	viper.SetConfigName("config")
	viper.AddConfigPath(".")
	viper.SetConfigType("json")

	if err := viper.ReadInConfig(); err != nil {
		return nil, fmt.Errorf("error reading config file: %w", err)
	}

	var cfg Config
	if err := viper.Unmarshal(&cfg); err != nil {
		return nil, fmt.Errorf("unable to decode into struct: %w", err)
	}

	return &cfg, nil
}

type Config struct {
	Host        string `json:"host"`
	Port        int    `json:"port"`
	User        string `json:"user"`
	Password    string `json:"password"`
	LocalDBPath string `json:"local_db_path"`
}
type Indexer struct {
	cfg    Config
	db     *leveldb.DB
	client *rpc.Client
	logger zerolog.Logger
	wg     *sync.WaitGroup
	stop   chan struct{}
}

// NewIndexer creates a new Indexer instance with the given configuration.
func NewIndexer(cfg Config) (*Indexer, error) {
	db, err := NewLevelDB(cfg.LocalDBPath, true)
	if err != nil {
		return nil, fmt.Errorf("failed to create level db: %w", err)
	}
	client, err := newClient(cfg.Host, cfg.User, cfg.Password)
	if err != nil {
		if dbCloseErr := db.Close(); dbCloseErr != nil {
			log.Error().Err(dbCloseErr).Str("module", "bitcoin_indexer").Msg("failed to close leveldb after rpc client creation error")
		}
		return nil, fmt.Errorf("failed to create rpc client: %w", err)
	}
	indexer := &Indexer{
		cfg:    cfg,
		db:     db,
		client: client,
		logger: log.With().Str("module", "bitcoin_indexer").Logger(),
		wg:     &sync.WaitGroup{},
		stop:   make(chan struct{}),
	}
	return indexer, nil
}

// newClient returns a client connection to a UTXO daemon.
func newClient(host, user, password string) (*rpc.Client, error) {
	authFn := func(h http.Header) error {
		auth := base64.StdEncoding.EncodeToString([]byte(user + ":" + password))
		h.Set("Authorization", fmt.Sprintf("Basic %s", auth))
		return nil
	}

	// default to http if no scheme is specified
	if !strings.Contains(host, "://") {
		host = "http://" + host
	}

	c, err := rpc.DialOptions(context.Background(), host, rpc.WithHTTPAuth(authFn))
	if err != nil {
		return nil, err
	}

	return c, nil
}

func (i *Indexer) getStartBlockHeight() (int64, error) {
	value, err := i.db.Get([]byte("start_block_height"), nil)
	if err != nil {
		if errors.Is(err, leveldb.ErrNotFound) {
			return 0, nil
		}
		return 0, fmt.Errorf("failed to get start block height: %w", err)
	}
	height, err := strconv.ParseInt(string(value), 10, 64)
	if err != nil {
		return 0, fmt.Errorf("failed to parse start block height: %w", err)
	}
	return height, nil
}

// setStartBlockHeight saves an int64 to LevelDB under the key "start_block_height".
// It stores the value as a decimal string (e.g. "12345").
func (i *Indexer) setStartBlockHeight(height int64) error {
	b := []byte(fmt.Sprintf("%d", height))
	if err := i.db.Put([]byte("start_block_height"), b, nil); err != nil {
		return fmt.Errorf("failed to set start block height: %w", err)
	}
	return nil
}

func (i *Indexer) Start() error {
	// Minimal startup: read the stored start block height and log it.
	height, err := i.getStartBlockHeight()
	if err != nil {
		return err
	}
	i.logger.Info().Int64("start_block_height", height).Msg("indexer starting from block")
	i.wg.Add(1)
	go i.DownloadBlocks(height)
	return nil
}
func (i *Indexer) Stop() {
	close(i.stop)
	i.wg.Wait()
	if err := i.db.Close(); err != nil {
		i.logger.Error().Err(err).Str("module", "bitcoin_indexer").Msg("failed to close leveldb")
	} else {
		i.logger.Info().Str("module", "bitcoin_indexer").Msg("leveldb closed")
	}
	i.logger.Info().Str("module", "bitcoin_indexer").Msg("indexer stopped")
}

func (i *Indexer) shouldBackoff(err error) bool {
	var rpcError *btcjson.RPCError
	ok := errors.As(err, &rpcError)
	return ok && rpcError.Code == btcjson.ErrRPCBlockNotFound
}

func (i *Indexer) DownloadBlocks(startHeight int64) {
	defer i.wg.Done()
	currentHeight := startHeight
	i.logger.Info().Str("module", "bitcoin_indexer").Msgf("indexer starting from block height: %d", startHeight)
	defer func() {
		// save the current height to db on exit
		if err := i.setStartBlockHeight(currentHeight); err != nil {
			i.logger.Error().Err(err).Str("module", "bitcoin_indexer").Msg("failed to save current block height on shutdown")
		} else {
			i.logger.Info().Int64("block_height", currentHeight).Str("module", "bitcoin_indexer").Msg("saved current block height on shutdown")
		}
	}()
	for {
		select {
		case <-i.stop:
			i.logger.Info().Str("module", "bitcoin_indexer").Msg("stopping block download")
			return
		default:
			hash, err := i.GetBlockHash(currentHeight)
			if err != nil {
				if i.shouldBackoff(err) {
					// back off
					time.Sleep(time.Second)
					continue
				}
				i.logger.Error().Err(err).Str("module", "bitcoin_indexer").Msg("failed to get block hash")
				continue
			}
			block, err := i.GetBlockVerboseTxs(hash)
			if err != nil {
				if i.shouldBackoff(err) {
					// back off
					time.Sleep(time.Second)
					continue
				}
				i.logger.Error().Err(err).Str("module", "bitcoin_indexer").Msg("failed to get block")
				continue
			}
			for _, tx := range block.Tx {
				i.processTransaction(tx)
			}
			currentHeight++
		}
	}
}
func (i *Indexer) processTransaction(tx btcjson.TxRawResult) {
	// process vins
	i.processVIn(tx.Vin)

	// process vouts
	i.processVOuts(tx.Vout, tx.Txid)
}

func (i *Indexer) processVIn(ins []btcjson.Vin) {
	for _, in := range ins {
		// delete UTXO from db
		key := fmt.Sprintf("%s-%d", in.Txid, in.Vout)
		if err := i.db.Delete([]byte(key), nil); err != nil {
			i.logger.Err(err).Msgf("failed to delete key,txid: %s", in.Txid)
		}
	}
}
func (i *Indexer) processVOuts(outs []btcjson.Vout, txid string) {
	for _, out := range outs {
		key := fmt.Sprintf("%s-%d", txid, out.N)
		value := strconv.FormatFloat(out.Value, 'f', 8, 64)
		if err := i.db.Put([]byte(key), []byte(value), nil); err != nil {
			i.logger.Err(err).Msgf("failed to put key,txid: %s", txid)
		}
	}
}

// GetBlockVerboseTxs returns information about the block with verbosity 2.
func (i *Indexer) GetBlockVerboseTxs(hash string) (*btcjson.GetBlockVerboseTxResult, error) {
	var block btcjson.GetBlockVerboseTxResult
	err := i.client.Call(&block, "getblock", hash, 2)
	return &block, extractBTCError(err)
}

// GetBlockHash returns the hash of the block in best-block-chain at the given height.
func (i *Indexer) GetBlockHash(height int64) (string, error) {
	var hash string
	err := i.client.Call(&hash, "getblockhash", height)
	return hash, extractBTCError(err)
}

////////////////////////////////////////////////////////////////////////////////////////
// Helpers
////////////////////////////////////////////////////////////////////////////////////////

// Ethereum RPC returns an error with the response appended to the HTTP status like:
// 404 Not Found: {"error":{"code":-32601,"message":"Method not found"},"id":1}
//
// This makes best effort to extract and return the error as a btcjson.RPCError.
func extractBTCError(err error) error {
	if err == nil {
		return nil
	}

	// split the error into the HTTP status and the JSON response
	parts := strings.SplitN(err.Error(), ": ", 2)
	if len(parts) != 2 {
		return err
	}

	// parse the JSON response
	var response struct {
		Error struct {
			Code    btcjson.RPCErrorCode `json:"code"`
			Message string               `json:"message"`
		} `json:"error"`
	}
	if jsonErr := json.Unmarshal([]byte(parts[1]), &response); jsonErr != nil {
		return err
	}

	// return the error message
	return btcjson.NewRPCError(response.Error.Code, response.Error.Message)
}

// ExportUTXO writes DB entries that mention "utxo" in the key to the named file (base64-encoded values).
// If outPath is empty, it writes to stdout instead.
func (i *Indexer) ExportUTXO(outPath string) error {
	if outPath == "" {
		return fmt.Errorf("output filepath is empty")
	}
	f, err := os.Create(outPath)
	if err != nil {
		return fmt.Errorf("failed to create export file: %w", err)
	}
	// close file only if we created one (not stdout)
	defer func() {
		if f != nil {
			if err := f.Close(); err != nil {
				i.logger.Error().Err(err).Msg("failed to close export file")
			}
		}
	}()

	it := i.db.NewIterator(nil, nil)
	defer it.Release()
	for it.First(); it.Valid(); it.Next() {
		k := it.Key()
		v := it.Value()
		line := fmt.Sprintf("%s-%s\n", string(k), string(v))
		if _, err := f.WriteString(line); err != nil {
			return fmt.Errorf("failed to write export: %w", err)
		}
	}
	if err := it.Error(); err != nil {
		i.logger.Error().Err(err).Str("module", "bitcoin_indexer")
	}
	return nil
}
