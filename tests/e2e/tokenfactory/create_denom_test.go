package tokenfactory

import (
	"fmt"

	sdkmath "cosmossdk.io/math"

	"github.com/cosmos/cosmos-sdk/client/flags"
	clitestutil "github.com/cosmos/cosmos-sdk/testutil/cli"
	sdk "github.com/cosmos/cosmos-sdk/types"
	tokenfactorycli "github.com/cosmos/tokenfactory/x/tokenfactory/client/cli"
	tokenfactorytypes "github.com/cosmos/tokenfactory/x/tokenfactory/types"
)

func (s *TokenFactoryIntegrationSuite) TestCreateDenom() {
	val := s.network.Validators[0]
	valAddr := val.Address.String()

	// 1. Create a new factory denom with subdenom "mytoken".
	// Denom creation consumes 2_000_000 gas by default, so provide a high gas limit.
	createArgs := []string{
		"mytoken",
		fmt.Sprintf("--%s=%s", flags.FlagFrom, valAddr),
		fmt.Sprintf("--%s=true", flags.FlagSkipConfirmation),
		fmt.Sprintf("--%s=%s", flags.FlagBroadcastMode, flags.BroadcastSync),
		fmt.Sprintf("--%s=%d", flags.FlagGas, 3_000_000),
		fmt.Sprintf("--%s=%s", flags.FlagFees, sdk.NewCoins(sdk.NewCoin(s.cfg.BondDenom, sdkmath.NewInt(20_000_000))).String()),
	}

	out, err := clitestutil.ExecTestCLICmd(val.ClientCtx, tokenfactorycli.NewCreateDenomCmd(), createArgs)
	s.Require().NoError(err)

	var txResp sdk.TxResponse
	s.Require().NoError(val.ClientCtx.Codec.UnmarshalJSON(out.Bytes(), &txResp), "failed to unmarshal tx response")
	s.Require().Equal(uint32(0), txResp.Code, "tx failed: %s", txResp.RawLog)

	// 2. Wait for the tx to be included in a block.
	s.Require().NoError(s.network.WaitForNextBlock())
	s.Require().NoError(s.network.WaitForNextBlock())

	expectedDenom := fmt.Sprintf("factory/%s/mytoken", valAddr)

	// 3. Query denoms created by the validator.
	queryDenomsArgs := []string{
		valAddr,
		fmt.Sprintf("--%s=json", flags.FlagOutput),
	}

	denomsOut, err := clitestutil.ExecTestCLICmd(val.ClientCtx, tokenfactorycli.GetCmdDenomsFromCreator(), queryDenomsArgs)
	s.Require().NoError(err)

	var denomsResp tokenfactorytypes.QueryDenomsFromCreatorResponse
	s.Require().NoError(val.ClientCtx.Codec.UnmarshalJSON(denomsOut.Bytes(), &denomsResp))
	s.Require().Contains(denomsResp.Denoms, expectedDenom, "expected denom not found in creator's denoms")

	// 4. Query authority metadata for the newly created denom.
	queryMetaArgs := []string{
		expectedDenom,
		fmt.Sprintf("--%s=json", flags.FlagOutput),
	}

	metaOut, err := clitestutil.ExecTestCLICmd(val.ClientCtx, tokenfactorycli.GetCmdDenomAuthorityMetadata(), queryMetaArgs)
	s.Require().NoError(err)

	var metaResp tokenfactorytypes.QueryDenomAuthorityMetadataResponse
	s.Require().NoError(val.ClientCtx.Codec.UnmarshalJSON(metaOut.Bytes(), &metaResp))
	s.Require().Equal(valAddr, metaResp.AuthorityMetadata.Admin, "denom admin should be the creator")
}
