package cli

import (
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/cosmos/cosmos-sdk/client"
	"github.com/cosmos/cosmos-sdk/client/flags"
	"github.com/cosmos/cosmos-sdk/client/tx"
	"github.com/cosmos/cosmos-sdk/version"

	"github.com/btcq-org/qbtc/x/qbtc/types"
)

// GetTxCmd returns the transaction commands for the qbtc module.
func GetTxCmd() *cobra.Command {
	qbtcTxCmd := &cobra.Command{
		Use:                        types.ModuleName,
		Short:                      "qbtc transactions subcommands",
		DisableFlagParsing:         true,
		SuggestionsMinimumDistance: 2,
		RunE:                       client.ValidateCmd,
	}

	qbtcTxCmd.AddCommand(NewClaimWithProofCmd())

	return qbtcTxCmd
}

// NewClaimWithProofCmd builds a MsgClaimWithProof from a JSON file produced by
// the zkprover tool and broadcasts it. The JSON file must decode into the
// MsgClaimWithProof proto (all hash/proof fields hex-encoded). The tx signer
// (--from) pays fees; the ante FreeClaimDecorator waives them, so any funded
// key works — including a key that differs from the Claimer in the JSON.
func NewClaimWithProofCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "claim-with-proof [msg-json-file]",
		Short: "Claim tokens by submitting a ZK proof of Bitcoin address ownership",
		Long: strings.TrimSpace(fmt.Sprintf(`Submit a MsgClaimWithProof for the UTXOs listed in the JSON file.

The file must contain a JSON-encoded MsgClaimWithProof — typically produced by
the zkprover tool. Example:

  $ %s tx %s claim-with-proof claim.json --from user

`, version.AppName, types.ModuleName)),
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			clientCtx, err := client.GetClientTxContext(cmd)
			if err != nil {
				return err
			}

			raw, err := os.ReadFile(args[0])
			if err != nil {
				return fmt.Errorf("read msg file: %w", err)
			}

			msg := &types.MsgClaimWithProof{}
			if err := clientCtx.Codec.UnmarshalJSON(raw, msg); err != nil {
				return fmt.Errorf("decode MsgClaimWithProof: %w", err)
			}

			return tx.GenerateOrBroadcastTxCLI(clientCtx, cmd.Flags(), msg)
		},
	}

	flags.AddTxFlagsToCmd(cmd)
	return cmd
}
