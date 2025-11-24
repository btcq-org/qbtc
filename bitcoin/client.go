package bitcoin

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/btcsuite/btcd/btcjson"
	"github.com/ethereum/go-ethereum/rpc"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/syndtr/goleveldb/leveldb"
)

type BtcClient struct {
	cfg    Config
	db     *leveldb.DB
	client *rpc.Client
	logger zerolog.Logger
}

func NewBtcClient(cfg Config, db *leveldb.DB) (*BtcClient, error) {
	client, err := newClient(cfg.Host, cfg.Port, cfg.RPCUser, cfg.Password)
	if err != nil {
		return nil, fmt.Errorf("failed to create rpc client: %w", err)
	}
	return &BtcClient{
		cfg:    cfg,
		db:     db,
		client: client,
		logger: log.With().Str("module", "BtcClient").Logger(),
	}, nil
}

// newClient returns a client connection to a UTXO daemon.
func newClient(host string, port int64, user, password string) (*rpc.Client, error) {
	authFn := func(h http.Header) error {
		auth := base64.StdEncoding.EncodeToString([]byte(user + ":" + password))
		h.Set("Authorization", fmt.Sprintf("Basic %s", auth))
		return nil
	}

	// default to http if no scheme is specified
	if !strings.Contains(host, "://") {
		host = "http://" + host
	}
	if port != 80 && port != 443 {
		host = fmt.Sprintf("%s:%d", host, port)
	}
	c, err := rpc.DialOptions(context.Background(), host, rpc.WithHTTPAuth(authFn))
	if err != nil {
		return nil, err
	}

	return c, nil
}
func (c *BtcClient) GetStartBlockHeight() (int64, error) {
	value, err := c.db.Get([]byte("start_block_height"), nil)
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
func (c *BtcClient) SetStartBlockHeight(height int64) error {
	b := []byte(fmt.Sprintf("%d", height))
	if err := c.db.Put([]byte("start_block_height"), b, nil); err != nil {
		return fmt.Errorf("failed to set start block height: %w", err)
	}
	return nil
}
func (c *BtcClient) ShouldBackoff(err error) bool {
	var rpcError *btcjson.RPCError
	ok := errors.As(err, &rpcError)
	if strings.Contains(err.Error(), "Block not available") || strings.Contains(err.Error(), "Block height out of range") {
		return true
	}
	return ok && (rpcError.Code == btcjson.ErrRPCBlockNotFound || strings.Contains(rpcError.Message, "Block not available"))
}

// GetBlockVerboseTxs returns information about the block with verbosity 2.
func (c *BtcClient) GetBlockVerboseTxs(hash string) (*btcjson.GetBlockVerboseTxResult, error) {
	var block btcjson.GetBlockVerboseTxResult
	err := c.client.Call(&block, "getblock", hash, 2)
	return &block, extractBTCError(err)
}

// GetBlockHash returns the hash of the block in best-block-chain at the given height.
func (c *BtcClient) GetBlockHash(height int64) (string, error) {
	var hash string
	err := c.client.Call(&hash, "getblockhash", height)
	return hash, extractBTCError(err)
}

func (c *BtcClient) Close() error {
	if c.client != nil {
		c.client.Close()
		c.logger.Info().Msg("rpc client closed")
	}
	return nil
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
