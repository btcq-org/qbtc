package config

import (
	"fmt"

	"github.com/btcq-org/qbtc/bitcoin"
	"github.com/spf13/viper"
)

type Config struct {
	ListenAddr       string         `mapstructure:"listen_addr" json:"listen_addr"`
	ExternalIP       string         `mapstructure:"external_ip" json:"external_ip"`
	RootPath         string         `mapstructure:"root_path" json:"root_path"`
	KeyName          string         `mapstructure:"key_name" json:"key_name"`
	StartBlockHeight int64          `mapstructure:"start_block_height" json:"start_block_height"`
	BitcoinConfig    bitcoin.Config `mapstructure:"bitcoin" json:"bitcoin"`
}

type P2PConfig struct {
	Port       int    `json:"port"`
	ExternalIP string `json:"external_ip"`
}

func DefaultConfig() *Config {
	return &Config{
		ListenAddr:       "0.0.0.0:30006",
		ExternalIP:       "",
		RootPath:         ".bifrost",
		KeyName:          "bifrost-p2p-key",
		StartBlockHeight: 0,
		BitcoinConfig: bitcoin.Config{
			Host:        "localhost",
			Port:        8332,
			RPCUser:     "user",
			Password:    "password",
			LocalDBPath: "./db",
		},
	}
}

// GetConfig reads the config file and returns a Config struct
func GetConfig() (*Config, error) {
	viper.SetConfigName("config")
	viper.AddConfigPath(".")
	viper.SetConfigType("json")
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
