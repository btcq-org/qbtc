package config

import (
	"fmt"

	"github.com/spf13/viper"
)

type Config struct {
	ListenAddr string `mapstructure:"listen_addr" json:"listen_addr"`
	ExternalIP string `mapstructure:"external_ip" json:"external_ip"`
	RootPath   string `mapstructure:"root_path" json:"root_path"`
	KeyName    string `mapstructure:"key_name" json:"key_name"`
}

type P2PConfig struct {
	Port       int    `json:"port"`
	ExternalIP string `json:"external_ip"`
}

func DefaultConfig() *Config {
	return &Config{
		ListenAddr: "0.0.0.0:30006",
		ExternalIP: "",
		RootPath:   ".bifrost",
		KeyName:    "bifrost-p2p-key",
	}
}

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
