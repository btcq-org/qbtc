package config

import (
	"fmt"
	"os"

	"github.com/btcq-org/qbtc/bitcoin"
	"github.com/spf13/viper"
)

type Config struct {
	ListenAddr        string         `mapstructure:"listen_addr" json:"listen_addr"`
	HTTPListenAddress string         `mapstructure:"http_listen_addr" json:"http_listen_addr"`
	ExternalIP        string         `mapstructure:"external_ip" json:"external_ip"`
	RootPath          string         `mapstructure:"root_path" json:"root_path"`
	KeyName           string         `mapstructure:"key_name" json:"key_name"`
	StartBlockHeight  int64          `mapstructure:"start_block_height" json:"start_block_height"`
	BitcoinConfig     bitcoin.Config `mapstructure:"bitcoin" json:"bitcoin"`
	QBTCHome          string         `mapstructure:"qbtc_home" json:"qbtc_home"`
	EbifrostAddress   string         `mapstructure:"ebifrost_address" json:"ebifrost_address"`
	QBTCGRPCAddress   string         `mapstructure:"qbtc_grpc_address" json:"qbtc_grpc_address"`
}

type P2PConfig struct {
	Port       int    `json:"port"`
	ExternalIP string `json:"external_ip"`
}

func DefaultConfig() *Config {
	return &Config{
		ListenAddr:        "0.0.0.0:30006",
		HTTPListenAddress: "0.0.0.0:30007",
		ExternalIP:        "",
		RootPath:          ".bifrost",
		KeyName:           "bifrost-p2p-key",
		StartBlockHeight:  0,
		BitcoinConfig: bitcoin.Config{
			Host:        "localhost",
			Port:        8332,
			RPCUser:     "user",
			Password:    "password",
			LocalDBPath: "./db",
		},
		EbifrostAddress: "localhost:50051",
		QBTCGRPCAddress: "localhost:9090",
	}
}

// GetConfig reads the config file and returns a Config struct
func GetConfig(configPath ...string) (*Config, error) {
	viper.Reset() // Reset viper to avoid state from previous calls
	viper.SetConfigType("json")

	// look for config in the given path
	// if path is a directory, look for config.json in that directory
	// if path is a file, use it directly
	if len(configPath) == 1 {
		path := configPath[0]
		info, err := os.Stat(path)
		if err != nil {
			return nil, fmt.Errorf("error accessing config path %s: %w", path, err)
		}
		if info.IsDir() {
			viper.SetConfigName("config")
			viper.AddConfigPath(path)
		} else {
			// If it's a file, use it directly
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
		return nil, fmt.Errorf("unable to decode into struct: %w", err)
	}

	return &cfg, nil
}
