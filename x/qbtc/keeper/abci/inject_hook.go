//go:build !vetest_malicious

package abci

import (
	sdk "github.com/cosmos/cosmos-sdk/types"

	"github.com/btcq-org/qbtc/x/qbtc/types"
)

// mutateInjectedMsg is the hook end-to-end tests use to make a validator
// propose a bad MsgBtcBlock. Production builds return msg unchanged.
func mutateInjectedMsg(_ sdk.Context, msg *types.MsgBtcBlock) *types.MsgBtcBlock { return msg }
