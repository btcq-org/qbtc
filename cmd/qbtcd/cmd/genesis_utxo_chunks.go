package cmd

import (
	"bufio"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/cosmos/cosmos-sdk/client"
	"github.com/cosmos/cosmos-sdk/x/genutil"
	genutiltypes "github.com/cosmos/cosmos-sdk/x/genutil/types"
	"github.com/spf13/cobra"

	"github.com/btcq-org/qbtc/x/qbtc/types"
)

// NewSetUtxoChunkHashesCmd returns `qbtcd genesis set-utxo-chunk-hashes`,
// which splits a genesis UTXO file the way the node does at InitChain and
// writes the hash of each chunk into the qbtc genesis state. Every node checks
// its genesis.bin and each chunk it loads against these hashes.
func NewSetUtxoChunkHashesCmd(defaultNodeHome string) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "set-utxo-chunk-hashes [genesis.bin]",
		Short: "Write the hashes of a genesis UTXO file's chunks into genesis.json",
		Long: fmt.Sprintf(`Split the UTXO snapshot file the way the node does at InitChain, into chunks
of %d UTXOs, and write the SHA-256 of each chunk to the qbtc module's
utxo_chunk_hashes in genesis.json. The file defaults to config/genesis.bin in
the node home. Publish the same genesis.json and genesis.bin to every node.`, types.UtxosPerChunk),
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			clientCtx := client.GetClientContextFromCmd(cmd)
			home := clientCtx.HomeDir
			if home == "" {
				home = defaultNodeHome
			}
			utxoFile := filepath.Join(home, "config", "genesis.bin")
			if len(args) == 1 {
				utxoFile = args[0]
			}

			f, err := os.Open(utxoFile)
			if err != nil {
				return err
			}
			defer f.Close()
			hashes, err := types.UtxoChunkHashes(bufio.NewReader(f))
			if err != nil {
				return fmt.Errorf("%s: %w", utxoFile, err)
			}

			genFile := filepath.Join(home, "config", "genesis.json")
			appGenesis, err := genutiltypes.AppGenesisFromFile(genFile)
			if err != nil {
				return err
			}
			var appState map[string]json.RawMessage
			if err := json.Unmarshal(appGenesis.AppState, &appState); err != nil {
				return fmt.Errorf("failed to unmarshal app state: %w", err)
			}
			var qbtcGenesis types.GenesisState
			if raw, ok := appState[types.ModuleName]; ok {
				if err := clientCtx.Codec.UnmarshalJSON(raw, &qbtcGenesis); err != nil {
					return fmt.Errorf("failed to unmarshal %s genesis state: %w", types.ModuleName, err)
				}
			}
			qbtcGenesis.UtxoChunkHashes = hashes
			raw, err := clientCtx.Codec.MarshalJSON(&qbtcGenesis)
			if err != nil {
				return err
			}
			appState[types.ModuleName] = raw
			if appGenesis.AppState, err = json.Marshal(appState); err != nil {
				return err
			}
			if err := genutil.ExportGenesisFile(appGenesis, genFile); err != nil {
				return err
			}

			for i, hash := range hashes {
				cmd.Printf("chunk %d: %s\n", i, hex.EncodeToString(hash))
			}
			cmd.Printf("wrote %d utxo_chunk_hashes to %s\n", len(hashes), genFile)
			return nil
		},
	}
	return cmd
}
