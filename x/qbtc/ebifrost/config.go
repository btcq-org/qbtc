package ebifrost

import (
	"fmt"
	"time"

	"github.com/spf13/cast"
	"github.com/spf13/cobra"

	servertypes "github.com/cosmos/cosmos-sdk/server/types"
)

const (
	flagEnabled          = "ebifrost.enable"
	flagBitcoinHost      = "ebifrost.bitcoin_host"
	flagBitcoinPort      = "ebifrost.bitcoin_port"
	flagBitcoinRPCUser   = "ebifrost.bitcoin_rpc_user"
	flagBitcoinPassword  = "ebifrost.bitcoin_password"
	flagMinConfirmations = "ebifrost.min_confirmations"
	flagPollInterval     = "ebifrost.poll_interval"
)

// EBifrostConfig configures the embedded Bitcoin observer. Each validator node
// observes Bitcoin directly via its own RPC endpoint and attests the resulting
// minimal block deltas through ABCI vote extensions.
type EBifrostConfig struct {
	Enable bool `json:"enable"`

	// Bitcoin RPC connection. When BitcoinHost is empty the observer stays idle
	// and the node simply attests empty vote extensions.
	BitcoinHost     string `json:"bitcoin_host"`
	BitcoinPort     int64  `json:"bitcoin_port"`
	BitcoinRPCUser  string `json:"bitcoin_rpc_user"`
	BitcoinPassword string `json:"bitcoin_password"`

	// MinConfirmations keeps the observer this many blocks behind the Bitcoin
	// tip, so attested blocks are deep enough to be reorg-safe.
	MinConfirmations int64 `json:"min_confirmations"`
	// PollInterval is how often the observer checks for new Bitcoin blocks.
	PollInterval time.Duration `json:"poll_interval"`
}

func DefaultEBifrostConfig() EBifrostConfig {
	return EBifrostConfig{
		Enable:           true,
		BitcoinHost:      "",
		BitcoinPort:      8332,
		BitcoinRPCUser:   "",
		BitcoinPassword:  "",
		MinConfirmations: 6,
		PollInterval:     10 * time.Second,
	}
}

// ConfigTemplate toml snippet for app.toml
func ConfigTemplate(c EBifrostConfig) string {
	return fmt.Sprintf(`
[ebifrost]
# Whether the embedded Bitcoin observer is enabled. When enabled and a Bitcoin
# RPC host is configured, the node observes Bitcoin blocks and attests them via
# ABCI vote extensions.
enable = %t

# Bitcoin RPC connection used by the embedded observer. Leave bitcoin_host empty
# to disable observation (the node will attest empty vote extensions).
bitcoin_host = "%s"
bitcoin_port = %d
bitcoin_rpc_user = "%s"
bitcoin_password = "%s"

# Keep the observer this many blocks behind the Bitcoin tip (reorg safety).
min_confirmations = %d

# How often to poll Bitcoin for new blocks.
poll_interval = "%s"
`, c.Enable, c.BitcoinHost, c.BitcoinPort, c.BitcoinRPCUser, c.BitcoinPassword, c.MinConfirmations, c.PollInterval.String())
}

func DefaultConfigTemplate() string {
	return ConfigTemplate(DefaultEBifrostConfig())
}

// ____________________________________________________________________________

// AddModuleInitFlags implements servertypes.ModuleInitFlags interface.
func AddModuleInitFlags(startCmd *cobra.Command) {
	defaults := DefaultEBifrostConfig()
	startCmd.Flags().Bool(flagEnabled, defaults.Enable, "Enable the embedded Bitcoin observer")
	startCmd.Flags().String(flagBitcoinHost, defaults.BitcoinHost, "Bitcoin RPC host for the embedded observer")
	startCmd.Flags().Int64(flagBitcoinPort, defaults.BitcoinPort, "Bitcoin RPC port for the embedded observer")
	startCmd.Flags().String(flagBitcoinRPCUser, defaults.BitcoinRPCUser, "Bitcoin RPC user for the embedded observer")
	startCmd.Flags().String(flagBitcoinPassword, defaults.BitcoinPassword, "Bitcoin RPC password for the embedded observer")
	startCmd.Flags().Int64(flagMinConfirmations, defaults.MinConfirmations, "Blocks to stay behind the Bitcoin tip")
	startCmd.Flags().Duration(flagPollInterval, defaults.PollInterval, "How often to poll Bitcoin for new blocks")
}

// ReadEBifrostConfig reads the ebifrost specific configuration
func ReadEBifrostConfig(opts servertypes.AppOptions) (EBifrostConfig, error) {
	cfg := DefaultEBifrostConfig()

	if v := opts.Get(flagEnabled); v != nil {
		var err error
		if cfg.Enable, err = cast.ToBoolE(v); err != nil {
			return cfg, err
		}
	}
	if v := opts.Get(flagBitcoinHost); v != nil {
		var err error
		if cfg.BitcoinHost, err = cast.ToStringE(v); err != nil {
			return cfg, err
		}
	}
	if v := opts.Get(flagBitcoinPort); v != nil {
		var err error
		if cfg.BitcoinPort, err = cast.ToInt64E(v); err != nil {
			return cfg, err
		}
	}
	if v := opts.Get(flagBitcoinRPCUser); v != nil {
		var err error
		if cfg.BitcoinRPCUser, err = cast.ToStringE(v); err != nil {
			return cfg, err
		}
	}
	if v := opts.Get(flagBitcoinPassword); v != nil {
		var err error
		if cfg.BitcoinPassword, err = cast.ToStringE(v); err != nil {
			return cfg, err
		}
	}
	if v := opts.Get(flagMinConfirmations); v != nil {
		var err error
		if cfg.MinConfirmations, err = cast.ToInt64E(v); err != nil {
			return cfg, err
		}
	}
	if v := opts.Get(flagPollInterval); v != nil {
		switch t := v.(type) {
		case time.Duration:
			cfg.PollInterval = t
		case string:
			parsed, err := time.ParseDuration(t)
			if err != nil {
				return cfg, err
			}
			cfg.PollInterval = parsed
		default:
			return cfg, fmt.Errorf("expected duration or string for %s, got %T", flagPollInterval, v)
		}
	}
	return cfg, nil
}
