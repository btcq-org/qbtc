package config

import (
	"fmt"
	"os"

	"github.com/spf13/viper"
)

// Config holds the configuration for the proof-service.
type Config struct {
	// HTTPListenAddr is the address the HTTP server listens on.
	HTTPListenAddr string `mapstructure:"http_listen_addr" json:"http_listen_addr"`

	// SetupDir is the directory containing ZK setup files (circuit.cs, proving.key).
	SetupDir string `mapstructure:"setup_dir" json:"setup_dir"`

	// ChainID is the chain ID for message binding (e.g., "qbtc-1").
	ChainID string `mapstructure:"chain_id" json:"chain_id"`

	// RequestTimeoutSec is the maximum time allowed for proof generation.
	RequestTimeoutSec int `mapstructure:"request_timeout_sec" json:"request_timeout_sec"`

	// BroadcastGRPCAddr is the gRPC endpoint of the qbtc node to broadcast to (e.g. "localhost:9090").
	// Leave empty to disable on-chain broadcasting.
	BroadcastGRPCAddr string `mapstructure:"broadcast_grpc_addr" json:"broadcast_grpc_addr,omitempty"`

	// BroadcastPrivKeyHexList is a list of hex-encoded secp256k1 private keys used to sign and
	// broadcast claim txs. Keys are selected in round-robin order. Leave empty to disable broadcasting.
	BroadcastPrivKeyHexList []string `mapstructure:"broadcast_priv_key_hex_list" json:"broadcast_priv_key_hex_list,omitempty"`
}

// DefaultConfig returns a Config with sensible defaults.
func DefaultConfig() *Config {
	return &Config{
		HTTPListenAddr:    "0.0.0.0:8090",
		SetupDir:          "./zk-setup",
		ChainID:           "qbtc-1",
		RequestTimeoutSec: 300,
	}
}

// GetConfig loads configuration from the specified path.
// If configPath is a directory, it looks for config.json inside it.
// If configPath is empty, it looks for config.json in the current directory.
func GetConfig(configPath ...string) (*Config, error) {
	viper.Reset()
	viper.SetConfigType("json")

	if len(configPath) == 1 && configPath[0] != "" {
		path := configPath[0]
		info, err := os.Stat(path)
		if err != nil {
			return nil, fmt.Errorf("error accessing config path %s: %w", path, err)
		}
		if info.IsDir() {
			viper.SetConfigName("config")
			viper.AddConfigPath(path)
		} else {
			viper.SetConfigFile(path)
		}
	} else {
		viper.SetConfigName("config")
		viper.AddConfigPath(".")
	}

	viper.AutomaticEnv()

	if err := viper.ReadInConfig(); err != nil {
		return nil, fmt.Errorf("error reading config file: %w", err)
	}

	var cfg Config
	if err := viper.Unmarshal(&cfg); err != nil {
		return nil, fmt.Errorf("unable to decode config into struct: %w", err)
	}

	return &cfg, nil
}
