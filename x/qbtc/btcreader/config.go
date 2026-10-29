package btcreader

import (
	"fmt"
	"time"

	"github.com/spf13/cast"
	"github.com/spf13/cobra"

	servertypes "github.com/cosmos/cosmos-sdk/server/types"
)

const (
	flagEnabled           = "btc_reader.enable"
	flagBitcoinHost       = "btc_reader.bitcoin_host"
	flagBitcoinPort       = "btc_reader.bitcoin_port"
	flagBitcoinRPCUser    = "btc_reader.bitcoin_rpc_user"
	flagBitcoinRPCPass    = "btc_reader.bitcoin_rpc_password"
	flagConfirmationDepth = "btc_reader.confirmation_depth"
	flagPollInterval      = "btc_reader.poll_interval"
	flagMaxCachedBlocks   = "btc_reader.max_cached_blocks"
	flagRPCTimeout        = "btc_reader.rpc_timeout"
)

// Config configures the in-node Bitcoin reader.
type Config struct {
	Enable             bool          `mapstructure:"enable" json:"enable"`
	BitcoinHost        string        `mapstructure:"bitcoin_host" json:"bitcoin_host"`
	BitcoinPort        int64         `mapstructure:"bitcoin_port" json:"bitcoin_port"`
	BitcoinRPCUser     string        `mapstructure:"bitcoin_rpc_user" json:"bitcoin_rpc_user"`
	BitcoinRPCPassword string        `mapstructure:"bitcoin_rpc_password" json:"bitcoin_rpc_password"`
	ConfirmationDepth  uint64        `mapstructure:"confirmation_depth" json:"confirmation_depth"`
	PollInterval       time.Duration `mapstructure:"poll_interval" json:"poll_interval"`
	MaxCachedBlocks    int           `mapstructure:"max_cached_blocks" json:"max_cached_blocks"`
	RPCTimeout         time.Duration `mapstructure:"rpc_timeout" json:"rpc_timeout"`
}

func DefaultConfig() Config {
	return Config{
		Enable:            false,
		BitcoinHost:       "localhost",
		BitcoinPort:       8332,
		ConfirmationDepth: 6,
		PollInterval:      10 * time.Second,
		MaxCachedBlocks:   16,
		RPCTimeout:        30 * time.Second,
	}
}

// Validate checks the settings the reader needs when it is enabled.
func (c Config) Validate() error {
	if !c.Enable {
		return nil
	}
	if c.BitcoinHost == "" {
		return fmt.Errorf("btc_reader.bitcoin_host is required")
	}
	if c.ConfirmationDepth == 0 {
		return fmt.Errorf("btc_reader.confirmation_depth must be at least 1")
	}
	if c.PollInterval <= 0 {
		return fmt.Errorf("btc_reader.poll_interval must be positive")
	}
	if c.MaxCachedBlocks < 1 {
		return fmt.Errorf("btc_reader.max_cached_blocks must be at least 1")
	}
	return nil
}

// ConfigTemplate toml snippet for app.toml
func ConfigTemplate(c Config) string {
	return fmt.Sprintf(`
[btc_reader]
# Whether this node reads Bitcoin blocks and attests them in its vote extensions.
# Validators must enable it and point it at a Bitcoin Core node they trust.
enable = %t

# Bitcoin Core RPC host and port
bitcoin_host = %q
bitcoin_port = %d

# Bitcoin Core RPC credentials
bitcoin_rpc_user = %q
bitcoin_rpc_password = %q

# Number of confirmations (the block itself counts as one) a Bitcoin block needs
# before this node attests it
confirmation_depth = %d

# How often to poll the Bitcoin node
poll_interval = "%s"

# Maximum number of Bitcoin blocks to keep ahead of the chain
max_cached_blocks = %d

# Timeout of each Bitcoin RPC request
rpc_timeout = "%s"
`, c.Enable, c.BitcoinHost, c.BitcoinPort, c.BitcoinRPCUser, c.BitcoinRPCPassword,
		c.ConfirmationDepth, c.PollInterval.String(), c.MaxCachedBlocks, c.RPCTimeout.String())
}

func DefaultConfigTemplate() string {
	return ConfigTemplate(DefaultConfig())
}

// ____________________________________________________________________________

// AddModuleInitFlags implements servertypes.ModuleInitFlags interface.
func AddModuleInitFlags(startCmd *cobra.Command) {
	defaults := DefaultConfig()
	startCmd.Flags().Bool(flagEnabled, defaults.Enable, "Read Bitcoin blocks and attest them in vote extensions")
	startCmd.Flags().String(flagBitcoinHost, defaults.BitcoinHost, "Bitcoin Core RPC host")
	startCmd.Flags().Int64(flagBitcoinPort, defaults.BitcoinPort, "Bitcoin Core RPC port")
	startCmd.Flags().String(flagBitcoinRPCUser, defaults.BitcoinRPCUser, "Bitcoin Core RPC user")
	startCmd.Flags().String(flagBitcoinRPCPass, defaults.BitcoinRPCPassword, "Bitcoin Core RPC password")
	startCmd.Flags().Uint64(flagConfirmationDepth, defaults.ConfirmationDepth, "Confirmations a Bitcoin block needs before it is attested")
	startCmd.Flags().Duration(flagPollInterval, defaults.PollInterval, "How often to poll the Bitcoin node")
	startCmd.Flags().Int(flagMaxCachedBlocks, defaults.MaxCachedBlocks, "Maximum number of Bitcoin blocks to keep ahead of the chain")
	startCmd.Flags().Duration(flagRPCTimeout, defaults.RPCTimeout, "Timeout of each Bitcoin RPC request")
}

// ReadConfig reads the [btc_reader] configuration
func ReadConfig(opts servertypes.AppOptions) (Config, error) {
	cfg := DefaultConfig()
	var err error

	if v := opts.Get(flagEnabled); v != nil {
		if cfg.Enable, err = cast.ToBoolE(v); err != nil {
			return cfg, fmt.Errorf("%s: %w", flagEnabled, err)
		}
	}
	if v := opts.Get(flagBitcoinHost); v != nil {
		if cfg.BitcoinHost, err = cast.ToStringE(v); err != nil {
			return cfg, fmt.Errorf("%s: %w", flagBitcoinHost, err)
		}
	}
	if v := opts.Get(flagBitcoinPort); v != nil {
		if cfg.BitcoinPort, err = cast.ToInt64E(v); err != nil {
			return cfg, fmt.Errorf("%s: %w", flagBitcoinPort, err)
		}
	}
	if v := opts.Get(flagBitcoinRPCUser); v != nil {
		if cfg.BitcoinRPCUser, err = cast.ToStringE(v); err != nil {
			return cfg, fmt.Errorf("%s: %w", flagBitcoinRPCUser, err)
		}
	}
	if v := opts.Get(flagBitcoinRPCPass); v != nil {
		if cfg.BitcoinRPCPassword, err = cast.ToStringE(v); err != nil {
			return cfg, fmt.Errorf("%s: %w", flagBitcoinRPCPass, err)
		}
	}
	if v := opts.Get(flagConfirmationDepth); v != nil {
		if cfg.ConfirmationDepth, err = cast.ToUint64E(v); err != nil {
			return cfg, fmt.Errorf("%s: %w", flagConfirmationDepth, err)
		}
	}
	if v := opts.Get(flagPollInterval); v != nil {
		if cfg.PollInterval, err = cast.ToDurationE(v); err != nil {
			return cfg, fmt.Errorf("%s: %w", flagPollInterval, err)
		}
	}
	if v := opts.Get(flagMaxCachedBlocks); v != nil {
		if cfg.MaxCachedBlocks, err = cast.ToIntE(v); err != nil {
			return cfg, fmt.Errorf("%s: %w", flagMaxCachedBlocks, err)
		}
	}
	if v := opts.Get(flagRPCTimeout); v != nil {
		if cfg.RPCTimeout, err = cast.ToDurationE(v); err != nil {
			return cfg, fmt.Errorf("%s: %w", flagRPCTimeout, err)
		}
	}
	return cfg, cfg.Validate()
}
