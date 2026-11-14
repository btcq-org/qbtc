package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	cmttypes "github.com/cometbft/cometbft/types"
	"github.com/cosmos/cosmos-sdk/client"
	moduletestutil "github.com/cosmos/cosmos-sdk/types/module/testutil"
	genutiltypes "github.com/cosmos/cosmos-sdk/x/genutil/types"
	protoio "github.com/cosmos/gogoproto/io"
	"github.com/stretchr/testify/require"

	"github.com/btcq-org/qbtc/x/qbtc/module"
	"github.com/btcq-org/qbtc/x/qbtc/types"
)

func TestSetUtxoChunkHashesCmd(t *testing.T) {
	home := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(home, "config"), 0o755))

	var utxoFile bytes.Buffer
	w := protoio.NewDelimitedWriter(&utxoFile)
	for _, txid := range []string{"aa", "bb", "cc"} {
		require.NoError(t, w.WriteMsg(&types.UTXO{Txid: txid, Amount: 10, EntitledAmount: 10}))
	}
	binPath := filepath.Join(home, "config", "genesis.bin")
	require.NoError(t, os.WriteFile(binPath, utxoFile.Bytes(), 0o644))
	want, err := types.UtxoChunkHashes(bytes.NewReader(utxoFile.Bytes()))
	require.NoError(t, err)

	encCfg := moduletestutil.MakeTestEncodingConfig(module.AppModule{})
	appState, err := json.Marshal(map[string]json.RawMessage{
		types.ModuleName: encCfg.Codec.MustMarshalJSON(&types.GenesisState{BtcInitialHeight: 7}),
		"bank":           json.RawMessage(`{}`),
	})
	require.NoError(t, err)
	appGenesis := genutiltypes.NewAppGenesisWithVersion("qbtc-test-1", appState)
	appGenesis.Consensus = &genutiltypes.ConsensusGenesis{Params: cmttypes.DefaultConsensusParams()}
	genFile := filepath.Join(home, "config", "genesis.json")
	require.NoError(t, appGenesis.SaveAs(genFile))

	cmd := NewSetUtxoChunkHashesCmd(home)
	clientCtx := client.Context{}.WithCodec(encCfg.Codec).WithHomeDir(home)
	ctx := context.WithValue(context.Background(), client.ClientContextKey, &clientCtx)
	cmd.SetContext(ctx)
	cmd.SetArgs(nil)
	cmd.SetOut(&bytes.Buffer{})
	require.NoError(t, cmd.Execute())

	written, err := genutiltypes.AppGenesisFromFile(genFile)
	require.NoError(t, err)
	var state map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(written.AppState, &state))
	var qbtcGenesis types.GenesisState
	require.NoError(t, encCfg.Codec.UnmarshalJSON(state[types.ModuleName], &qbtcGenesis))
	require.Equal(t, want, qbtcGenesis.UtxoChunkHashes)
	require.Equal(t, uint64(7), qbtcGenesis.BtcInitialHeight, "the rest of the qbtc genesis is kept")
	require.JSONEq(t, `{}`, string(state["bank"]), "other modules are kept")
}
