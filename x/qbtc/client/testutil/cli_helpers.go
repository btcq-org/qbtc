package testutil

import (
	"os"
	"path/filepath"

	"github.com/cosmos/cosmos-sdk/client"
	"github.com/cosmos/cosmos-sdk/testutil"
	clitestutil "github.com/cosmos/cosmos-sdk/testutil/cli"

	"github.com/btcq-org/qbtc/x/qbtc/client/cli"
	"github.com/btcq-org/qbtc/x/qbtc/types"
)

// MsgClaimWithProofExec serializes the given MsgClaimWithProof to a temp file
// and invokes `tx qbtc claim-with-proof` against it. This mirrors the shape of
// the SDK's clitestutil.MsgSendExec: a thin wrapper that other e2e suites can
// reuse without having to re-implement the file-based JSON plumbing.
//
// extraArgs must include at least --from, --skip-confirmation, --broadcast-mode,
// --chain-id, and --fees to match the way e2e suites drive the command.
func MsgClaimWithProofExec(
	clientCtx client.Context,
	msg *types.MsgClaimWithProof,
	extraArgs ...string,
) (testutil.BufferWriter, error) {
	bz, err := clientCtx.Codec.MarshalJSON(msg)
	if err != nil {
		return nil, err
	}

	tmpDir, err := os.MkdirTemp("", "qbtc-claim-msg")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(tmpDir)
	path := filepath.Join(tmpDir, "msg.json")
	if err := os.WriteFile(path, bz, 0o600); err != nil {
		return nil, err
	}

	args := append([]string{path}, extraArgs...)
	return clitestutil.ExecTestCLICmd(clientCtx, cli.NewClaimWithProofCmd(), args)
}
