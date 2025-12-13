package module

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/btcq-org/qbtc/x/qbtc/keeper"
	"github.com/btcq-org/qbtc/x/qbtc/types"
	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/cosmos/gogoproto/proto"
	"google.golang.org/protobuf/encoding/protowire"
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
	bufReader := bufio.NewReader(f)
	outputDir := filepath.Join(ul.DataDir, "utxo_chunks")
	if err := os.MkdirAll(outputDir, 0o755); err != nil {
		return err
	}
	chunkIndex := 0
	for {
		err := ul.LoadUtxosToChunkFile(ctx, bufReader, chunkIndex, outputDir)
		if err != nil {
			ctx.Logger().Info("spliting utxo files", "total", chunkIndex)
			if err == io.EOF || err == io.ErrUnexpectedEOF {
				return nil
			}
			return err
		}

		chunkIndex++
	}
}

func (ul *UtxoLoader) LoadUtxosToChunkFile(ctx sdk.Context, srcFileReader io.Reader, chunkIndex int, outputDir string) error {
	chunkFile := filepath.Join(outputDir, fmt.Sprintf("genesis_chunk_%d.bin", chunkIndex))
	outF, err := os.Create(chunkFile)
	if err != nil {
		return err
	}
	defer func() {
		if err := outF.Close(); err != nil {
			ctx.Logger().Error("failed to close out file", "error", err)
		}
	}()
	bufWriter := bufio.NewWriter(outF)
	// Read and write 1,000,000 UTXOs per chunk file
	for range 1000000 {
		utxoBytes, err := ul.readUtxo(srcFileReader)
		if err != nil {
			bufWriter.Flush()
			return err
		}

		if err := ul.writeUtxo(bufWriter, utxoBytes); err != nil {
			return err
		}
	}
	return nil
}
func (ul *UtxoLoader) readUtxo(reader io.Reader) ([]byte, error) {
	lengthBytes := make([]byte, protowire.SizeFixed32())
	n, err := io.ReadFull(reader, lengthBytes)
	if err != nil {
		return nil, err
	}
	if n < protowire.SizeFixed32() {
		return nil, io.EOF
	}
	size, n := protowire.ConsumeFixed32(lengthBytes)
	if n < 0 {
		return nil, fmt.Errorf("failed to read utxo size")
	}
	utxoBytes := make([]byte, size)
	n, err = io.ReadFull(reader, utxoBytes)
	if err != nil {
		return nil, err
	}
	if uint32(n) < size {
		return nil, io.EOF
	}
	return utxoBytes, nil
}

func (ul *UtxoLoader) writeUtxo(writer io.Writer, utxoData []byte) error {
	lengthBytes := protowire.AppendFixed32(nil, uint32(len(utxoData)))
	_, err := writer.Write(lengthBytes)
	if err != nil {
		return err
	}
	_, err = writer.Write(utxoData)
	return err
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
	bufReader := bufio.NewReader(f)
	for {
		utxoBytes, err := ul.readUtxo(bufReader)
		if err != nil {
			if err == io.EOF || err == io.ErrUnexpectedEOF {
				break
			}
			return err
		}
		var utxo types.UTXO
		if err := proto.Unmarshal(utxoBytes, &utxo); err != nil {
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
	}

	return nil
}
