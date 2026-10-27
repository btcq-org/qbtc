package ebifrost_test

import (
	"strings"
	"testing"
	"time"

	simtestutil "github.com/cosmos/cosmos-sdk/testutil/sims"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/require"

	"github.com/btcq-org/qbtc/x/qbtc/ebifrost"
)

func TestReadEBifrostConfigDefaults(t *testing.T) {
	cfg, err := ebifrost.ReadEBifrostConfig(simtestutil.AppOptionsMap{})
	require.NoError(t, err)
	require.Equal(t, ebifrost.DefaultEBifrostConfig(), cfg)
	require.False(t, cfg.Enable)
	require.Equal(t, uint64(6), cfg.ConfirmationDepth)
	require.Equal(t, 16, cfg.MaxCachedBlocks)
	require.Equal(t, 10*time.Second, cfg.PollInterval)
}

func TestReadEBifrostConfig(t *testing.T) {
	cfg, err := ebifrost.ReadEBifrostConfig(simtestutil.AppOptionsMap{
		"ebifrost.enable":               true,
		"ebifrost.bitcoin_host":         "btc.example",
		"ebifrost.bitcoin_port":         18443,
		"ebifrost.bitcoin_rpc_user":     "user",
		"ebifrost.bitcoin_rpc_password": "pass",
		"ebifrost.confirmation_depth":   3,
		"ebifrost.poll_interval":        "2s",
		"ebifrost.max_cached_blocks":    8,
		"ebifrost.rpc_timeout":          "5s",
	})
	require.NoError(t, err)
	require.Equal(t, ebifrost.EBifrostConfig{
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

func TestReadEBifrostConfigRejectsInvalid(t *testing.T) {
	for name, opts := range map[string]simtestutil.AppOptionsMap{
		"not a bool":      {"ebifrost.enable": "maybe"},
		"not a duration":  {"ebifrost.poll_interval": "soon"},
		"zero depth":      {"ebifrost.enable": true, "ebifrost.confirmation_depth": 0},
		"no cache":        {"ebifrost.enable": true, "ebifrost.max_cached_blocks": 0},
		"no poll":         {"ebifrost.enable": true, "ebifrost.poll_interval": "0s"},
		"no host":         {"ebifrost.enable": true, "ebifrost.bitcoin_host": ""},
		"negative number": {"ebifrost.bitcoin_port": "abc"},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := ebifrost.ReadEBifrostConfig(opts)
			require.Error(t, err)
		})
	}
	// a disabled reader needs no valid Bitcoin settings
	_, err := ebifrost.ReadEBifrostConfig(simtestutil.AppOptionsMap{"ebifrost.confirmation_depth": 0})
	require.NoError(t, err)
}

// The app.toml section parses back to the same settings.
func TestConfigTemplateIsValidToml(t *testing.T) {
	cfg := ebifrost.DefaultEBifrostConfig()
	cfg.Enable = true
	cfg.BitcoinRPCPassword = `p"ss\word`
	v := viper.New()
	v.SetConfigType("toml")
	require.NoError(t, v.ReadConfig(strings.NewReader(ebifrost.ConfigTemplate(cfg))))
	require.True(t, v.GetBool("ebifrost.enable"))
	require.Equal(t, `p"ss\word`, v.GetString("ebifrost.bitcoin_rpc_password"))
	require.Equal(t, int64(8332), v.GetInt64("ebifrost.bitcoin_port"))
	require.Equal(t, 10*time.Second, v.GetDuration("ebifrost.poll_interval"))
}
