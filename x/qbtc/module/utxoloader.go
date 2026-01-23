package module

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/btcq-org/qbtc/x/qbtc/keeper"
	"github.com/btcq-org/qbtc/x/qbtc/types"
	sdk "github.com/cosmos/cosmos-sdk/types"
	protoio "github.com/cosmos/gogoproto/io"
)

type UtxoLoader struct {
	DataDir string
}

func NewUtxoLoader(dataDir string) UtxoLoader {
	return UtxoLoader{
		DataDir: dataDir,
	}
}
func (ul *UtxoLoader) EnsureUtxoFileSplitted(ctx sdk.Context) error {
	initialUtxoFile := filepath.Join(ul.DataDir, "config", "genesis.bin")
	if _, err := os.Stat(initialUtxoFile); os.IsNotExist(err) {
		ctx.Logger().Info("no initial UTXO file found, skipping split")
		return nil
	}
	if err := ul.SplitUtxoFile(ctx); err != nil {
		return err
	}
	if err := os.Remove(initialUtxoFile); err != nil {
		return err
	}
	return nil
}

// SplitUtxoFile splits the large genesis.bin file into smaller files for easier handling.
func (ul *UtxoLoader) SplitUtxoFile(ctx sdk.Context) error {
	initialUtxoFile := filepath.Join(ul.DataDir, "config", "genesis.bin")
	f, err := os.Open(initialUtxoFile)
	if err != nil {
		return err
	}
	defer f.Close()
	reader := protoio.NewDelimitedReader(f, 50*1024*1024) // 50MB max message size
	outputDir := filepath.Join(ul.DataDir, "utxo_chunks")
	if err := os.MkdirAll(outputDir, 0o755); err != nil {
		return err
	}
	chunkIndex := 0
	for {
		err := ul.LoadUtxosToChunkFile(ctx, reader, chunkIndex, outputDir)
		if err != nil {
			ctx.Logger().Info("splitting utxo files", "total", chunkIndex, "chunk_index", chunkIndex)
			if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
				return nil
			}
			return err
		}

		chunkIndex++
	}
}

func (ul *UtxoLoader) LoadUtxosToChunkFile(ctx sdk.Context, genesisReader protoio.Reader, chunkIndex int, outputDir string) (err error) {
	chunkFile := filepath.Join(outputDir, fmt.Sprintf("genesis_chunk_%d.bin", chunkIndex))
	outF, createErr := os.Create(chunkFile)
	if createErr != nil {
		return createErr
	}

	bufferWriter := bufio.NewWriter(outF)
	writer := protoio.NewDelimitedWriter(bufferWriter)

	// ensure file is properly closed
	// and returning an error if there is a failure during file finalization
	defer func() {
		flushErr := bufferWriter.Flush()
		if flushErr != nil {
			ctx.Logger().Error("failed to flush to file", "flush_error", flushErr)
		}
		closeErr := outF.Close()
		if closeErr != nil {
			ctx.Logger().Error("failed to finalize file", "close_error", closeErr)
		}
		err = errors.Join(err, closeErr, flushErr)
	}()

	// Read and write 1,000,000 UTXOs per chunk file
	for range 1000000 {
		var utxo types.UTXO
		if err := genesisReader.ReadMsg(&utxo); err != nil {
			return fmt.Errorf("error reading utxo: %w", err)
		}

		if err := writer.WriteMsg(&utxo); err != nil {
			return fmt.Errorf("error writing utxo: %w", err)
		}
	}

	// close proto writer
	return writer.Close()
}
func (ul *UtxoLoader) EnsureLoadUtxoFromChunkFile(ctx sdk.Context, chunkIndex int, k *keeper.Keeper) error {
	chunkFile := filepath.Join(ul.DataDir, "utxo_chunks", fmt.Sprintf("genesis_chunk_%d.bin", chunkIndex))
	_, err := os.Stat(chunkFile)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	ctx.Logger().Info("loading utxo from chunk file", "file", chunkFile)
	if err := ul.LoadUtxosFromChunkFile(ctx, k, chunkFile); err != nil {
		return err
	}
	return os.Remove(chunkFile)
}

func (ul *UtxoLoader) LoadUtxosFromChunkFile(ctx sdk.Context, k *keeper.Keeper, chunkFile string) error {
	f, err := os.Open(chunkFile)
	if err != nil {
		return err
	}
	defer f.Close()
	reader := protoio.NewDelimitedReader(f, 50*1024*1024) // 50MB max message size
	processed := 0
	for {
		var utxo types.UTXO
		if err := reader.ReadMsg(&utxo); err != nil {
			if err == io.EOF || err == io.ErrUnexpectedEOF {
				ctx.Logger().Warn("break", "processed", processed, "err", err)
				break
			}
			return err
		}
		// This is the first UTXO , set it to already claimed , we need to mint 50 QBTC to start our genesis node
		if utxo.Txid == "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b" {
			utxo.EntitledAmount = 0
		}
		err = k.Utxoes.Set(ctx, utxo.GetKey(), utxo)
		if err != nil {
			return err
		}
		processed++
	}

	return nil
}
