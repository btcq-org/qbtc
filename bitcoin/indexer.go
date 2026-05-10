package bitcoin

import (
	"bufio"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/btcq-org/qbtc/x/qbtc/zk"
	qbtctypes "github.com/btcq-org/qbtc/x/qbtc/types"
	"github.com/btcsuite/btcd/btcjson"
	protoio "github.com/cosmos/gogoproto/io"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/syndtr/goleveldb/leveldb"
)

type Indexer struct {
	client *BtcClient
	db     *leveldb.DB
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
	btcClient, err := NewBtcClient(cfg, db)
	if err != nil {
		return nil, fmt.Errorf("failed to create BTC client: %w", err)
	}
	indexer := &Indexer{
		client: btcClient,
		db:     db,
		logger: log.With().Str("module", "bitcoin_indexer").Logger(),
		wg:     &sync.WaitGroup{},
		stop:   make(chan struct{}),
	}
	return indexer, nil
}

func (i *Indexer) Start() error {
	// Minimal startup: read the stored start block height and log it.
	height, err := i.client.GetStartBlockHeight()
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
		i.logger.Err(err).Msg("failed to close leveldb")
	} else {
		i.logger.Info().Msg("leveldb closed")
	}

	if err := i.client.Close(); err != nil {
		i.logger.Err(err).Msg("failed to close BTC client")
	}
	i.logger.Info().Str("module", "bitcoin_indexer").Msg("indexer stopped")
}

func (i *Indexer) DownloadBlocks(startHeight int64) {
	defer i.wg.Done()
	currentHeight := startHeight
	if currentHeight == 0 {
		currentHeight = 1 // Bitcoin block height starts from 1
	}
	i.logger.Info().Str("module", "bitcoin_indexer").Msgf("indexer starting from block height: %d", currentHeight)
	defer func() {
		// save the current height to db on exit
		if err := i.client.SetStartBlockHeight(currentHeight); err != nil {
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
			hash, err := i.client.GetBlockHash(currentHeight)
			if err != nil {
				if i.client.ShouldBackoff(err) {
					// back off
					time.Sleep(time.Second)
					continue
				}
				i.logger.Error().Err(err).Str("module", "bitcoin_indexer").Msg("failed to get block hash")
				continue
			}
			i.logger.Info().Str("module", "bitcoin_indexer").Msgf("block hash: %s", hash)
			block, err := i.client.GetBlockVerboseTxs(hash)
			if err != nil {
				if i.client.ShouldBackoff(err) {
					// back off
					time.Sleep(time.Second)
					continue
				}
				i.logger.Error().Err(err).Str("module", "bitcoin_indexer").Msg("failed to get block")
				continue
			}
			i.logger.Info().Str("module", "bitcoin_indexer").Msgf("(%d) txs in block height %d,hash: %s", len(block.Tx), block.Height, block.Hash)
			// process transactions
			for _, tx := range block.Tx {
				i.processTransaction(tx)
			}
			currentHeight++
			if err := i.client.SetStartBlockHeight(currentHeight); err != nil {
				i.logger.Error().Err(err).Str("module", "bitcoin_indexer").Msg("failed to save current block height on shutdown")
			}
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
		if out.Value <= 0 {
			continue
		}
		key := fmt.Sprintf("%s-%d", txid, out.N)
		outBuff, err := json.Marshal(out)
		if err != nil {
			i.logger.Err(err).Msgf("failed to marshal vout,txid: %s", txid)
			continue
		}
		if err := i.db.Put([]byte(key), outBuff, nil); err != nil {
			i.logger.Err(err).Msgf("failed to put key,txid: %s", txid)
		}
	}
}

// ExportUTXO writes DB entries that mention "utxo" in the key to the named file (base64-encoded values).
// If outPath is empty, it writes to stdout instead.
func (i *Indexer) ExportUTXO(outPath string) (err error) {
	if outPath == "" {
		return fmt.Errorf("output filepath is empty")
	}
	f, err := os.Create(outPath)
	if err != nil {
		return fmt.Errorf("failed to create export file: %w", err)
	}
	bufWriter := bufio.NewWriter(f)
	protoWriter := protoio.NewDelimitedWriter(bufWriter)
	// close file only if we created one (not stdout)
	defer func() {
		if f != nil {
			bufErr := bufWriter.Flush()
			if bufErr != nil {
				i.logger.Error().Err(bufErr).Msg("error flushing to file")
			}

			closeErr := f.Close()
			if closeErr != nil {
				i.logger.Error().Err(closeErr).Msg("error closing the export file")
			}
			// return final error
			err = errors.Join(err, closeErr, bufErr)
		}
	}()

	it := i.db.NewIterator(nil, nil)
	defer it.Release()
	idx := 0
	for it.First(); it.Valid(); it.Next() {
		k := it.Key()
		v := it.Value()
		if len(v) == 0 {
			continue
		}
		var vOut btcjson.Vout
		if err := json.Unmarshal(v, &vOut); err != nil {
			i.logger.Error().Err(err).Msg("failed to unmarshal vout during export")
			continue
		}
		fields := strings.Split(string(k), "-")
		txid, err := hex.DecodeString(fields[0])
		if err != nil || len(txid) != 32 {
			i.logger.Error().Err(err).Str("key", string(k)).Msg("invalid txid in indexer key")
			continue
		}
		// Skip outputs whose address type is not P2PKH/P2WPKH; the chain only
		// supports those.
		var addrBytes []byte
		if vOut.ScriptPubKey.Address != "" {
			h, herr := zk.BitcoinAddressToHash160(vOut.ScriptPubKey.Address)
			if herr != nil {
				continue
			}
			addrBytes = append(addrBytes, h[:]...)
		} else {
			continue
		}
		amount := uint64(vOut.Value * 1e8)
		pVout := qbtctypes.UTXO{
			Txid:           txid,
			Vout:           vOut.N,
			Amount:         amount,
			EntitledAmount: amount,
			Address:        addrBytes,
		}
		if err := protoWriter.WriteMsg(&pVout); err != nil {
			return err
		}
		idx++
		if idx%1000 == 0 {
			i.logger.Info().Int("count", idx).Msg("exported utxos")
		}
	}
	if err := it.Error(); err != nil {
		return fmt.Errorf("iterator error during export: %w", err)
	}
	err = protoWriter.Close()
	if err != nil {
		return fmt.Errorf("error closing protowriter: %w", err)
	}
	return nil
}
