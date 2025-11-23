package bitcoin

import (
	"fmt"

	"github.com/spf13/viper"
)

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

type Config struct {
	Host        string `mapstructure:"host" json:"host"`
	Port        int64  `mapstructure:"port" json:"port"`
	RPCUser     string `mapstructure:"rpc_user" json:"rpc_user"`
	Password    string `mapstructure:"password" json:"password"`
	LocalDBPath string `mapstructure:"local_db_path" json:"local_db_path"`
}
