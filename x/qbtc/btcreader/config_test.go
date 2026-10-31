package btcreader_test

import (
	"strings"
	"testing"
	"time"

	simtestutil "github.com/cosmos/cosmos-sdk/testutil/sims"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/require"

	"github.com/btcq-org/qbtc/x/qbtc/btcreader"
)

func TestReadConfigDefaults(t *testing.T) {
	cfg, err := btcreader.ReadConfig(simtestutil.AppOptionsMap{})
	require.NoError(t, err)
	require.Equal(t, btcreader.DefaultConfig(), cfg)
	require.False(t, cfg.Enable)
	require.Equal(t, uint64(6), cfg.ConfirmationDepth)
	require.Equal(t, 16, cfg.MaxCachedBlocks)
	require.Equal(t, 10*time.Second, cfg.PollInterval)
}

func TestReadConfig(t *testing.T) {
	cfg, err := btcreader.ReadConfig(simtestutil.AppOptionsMap{
		"btc_reader.enable":               true,
		"btc_reader.bitcoin_host":         "btc.example",
		"btc_reader.bitcoin_port":         18443,
		"btc_reader.bitcoin_rpc_user":     "user",
		"btc_reader.bitcoin_rpc_password": "pass",
		"btc_reader.confirmation_depth":   3,
		"btc_reader.poll_interval":        "2s",
		"btc_reader.max_cached_blocks":    8,
		"btc_reader.rpc_timeout":          "5s",
	})
	require.NoError(t, err)
	require.Equal(t, btcreader.Config{
		Enable:             true,
		BitcoinHost:        "btc.example",
		BitcoinPort:        18443,
		BitcoinRPCUser:     "user",
		BitcoinRPCPassword: "pass",
		ConfirmationDepth:  3,
		PollInterval:       2 * time.Second,
		MaxCachedBlocks:    8,
		RPCTimeout:         5 * time.Second,
	}, cfg)
}

func TestReadConfigRejectsInvalid(t *testing.T) {
	for name, opts := range map[string]simtestutil.AppOptionsMap{
		"not a bool":      {"btc_reader.enable": "maybe"},
		"not a duration":  {"btc_reader.poll_interval": "soon"},
		"zero depth":      {"btc_reader.enable": true, "btc_reader.confirmation_depth": 0},
		"no cache":        {"btc_reader.enable": true, "btc_reader.max_cached_blocks": 0},
		"no poll":         {"btc_reader.enable": true, "btc_reader.poll_interval": "0s"},
		"no host":         {"btc_reader.enable": true, "btc_reader.bitcoin_host": ""},
		"negative number": {"btc_reader.bitcoin_port": "abc"},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := btcreader.ReadConfig(opts)
			require.Error(t, err)
		})
	}
	// a disabled reader needs no valid Bitcoin settings
	_, err := btcreader.ReadConfig(simtestutil.AppOptionsMap{"btc_reader.confirmation_depth": 0})
	require.NoError(t, err)
}

// The app.toml section parses back to the same settings.
func TestConfigTemplateIsValidToml(t *testing.T) {
	cfg := btcreader.DefaultConfig()
	cfg.Enable = true
	cfg.BitcoinRPCPassword = `p"ss\word`
	v := viper.New()
	v.SetConfigType("toml")
	require.NoError(t, v.ReadConfig(strings.NewReader(btcreader.ConfigTemplate(cfg))))
	require.True(t, v.GetBool("btc_reader.enable"))
	require.Equal(t, `p"ss\word`, v.GetString("btc_reader.bitcoin_rpc_password"))
	require.Equal(t, int64(8332), v.GetInt64("btc_reader.bitcoin_port"))
	require.Equal(t, 10*time.Second, v.GetDuration("btc_reader.poll_interval"))
}
