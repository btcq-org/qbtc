package module

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"path/filepath"

	sdk "github.com/cosmos/cosmos-sdk/types"
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
		err := ul.LoadUtxosFromChunkFile(ctx, bufReader, chunkIndex, outputDir)
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

func (ul *UtxoLoader) LoadUtxosFromChunkFile(ctx sdk.Context, srcFileReader io.Reader, chunkIndex int, outputDir string) error {
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
	return append(lengthBytes, utxoBytes...), nil
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
