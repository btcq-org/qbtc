package qclient_test

import (
	"context"
	"fmt"
	"testing"

	"cosmossdk.io/math"
	"github.com/btcq-org/qbtc/bifrost/qclient"
	sdk "github.com/cosmos/cosmos-sdk/types"
	stakingtypes "github.com/cosmos/cosmos-sdk/x/staking/types"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
)

type mockStakingClient struct {
	validators   []stakingtypes.Validator
	bondedTokens math.Int
}

func (m *mockStakingClient) Validators(ctx context.Context, in *stakingtypes.QueryValidatorsRequest, opts ...grpc.CallOption) (*stakingtypes.QueryValidatorsResponse, error) {
	return &stakingtypes.QueryValidatorsResponse{
		Validators: m.validators,
	}, nil
}

func (m *mockStakingClient) Pool(ctx context.Context, in *stakingtypes.QueryPoolRequest, opts ...grpc.CallOption) (*stakingtypes.QueryPoolResponse, error) {
	return &stakingtypes.QueryPoolResponse{
		Pool: stakingtypes.Pool{
			BondedTokens:    m.bondedTokens,
			NotBondedTokens: math.ZeroInt(),
		},
	}, nil
}

// Other methods can return errors or empty responses for now
func (m *mockStakingClient) Validator(ctx context.Context, in *stakingtypes.QueryValidatorRequest, opts ...grpc.CallOption) (*stakingtypes.QueryValidatorResponse, error) {
	for _, validator := range m.validators {
		if validator.OperatorAddress == in.ValidatorAddr {
			return &stakingtypes.QueryValidatorResponse{
				Validator: validator,
			}, nil
		}
	}
	return nil, fmt.Errorf("not implemented")
}

func (m *mockStakingClient) ValidatorDelegations(ctx context.Context, in *stakingtypes.QueryValidatorDelegationsRequest, opts ...grpc.CallOption) (*stakingtypes.QueryValidatorDelegationsResponse, error) {
	return nil, fmt.Errorf("not implemented")
}

func (m *mockStakingClient) ValidatorUnbondingDelegations(ctx context.Context, in *stakingtypes.QueryValidatorUnbondingDelegationsRequest, opts ...grpc.CallOption) (*stakingtypes.QueryValidatorUnbondingDelegationsResponse, error) {
	return nil, fmt.Errorf("not implemented")
}

func (m *mockStakingClient) Delegation(ctx context.Context, in *stakingtypes.QueryDelegationRequest, opts ...grpc.CallOption) (*stakingtypes.QueryDelegationResponse, error) {
	return nil, fmt.Errorf("not implemented")
}

func (m *mockStakingClient) UnbondingDelegation(ctx context.Context, in *stakingtypes.QueryUnbondingDelegationRequest, opts ...grpc.CallOption) (*stakingtypes.QueryUnbondingDelegationResponse, error) {
	return nil, fmt.Errorf("not implemented")
}

func (m *mockStakingClient) DelegatorDelegations(ctx context.Context, in *stakingtypes.QueryDelegatorDelegationsRequest, opts ...grpc.CallOption) (*stakingtypes.QueryDelegatorDelegationsResponse, error) {
	return nil, fmt.Errorf("not implemented")
}

func (m *mockStakingClient) DelegatorUnbondingDelegations(ctx context.Context, in *stakingtypes.QueryDelegatorUnbondingDelegationsRequest, opts ...grpc.CallOption) (*stakingtypes.QueryDelegatorUnbondingDelegationsResponse, error) {
	return nil, fmt.Errorf("not implemented")
}

func (m *mockStakingClient) Redelegations(ctx context.Context, in *stakingtypes.QueryRedelegationsRequest, opts ...grpc.CallOption) (*stakingtypes.QueryRedelegationsResponse, error) {
	return nil, fmt.Errorf("not implemented")
}

func (m *mockStakingClient) DelegatorValidators(ctx context.Context, in *stakingtypes.QueryDelegatorValidatorsRequest, opts ...grpc.CallOption) (*stakingtypes.QueryDelegatorValidatorsResponse, error) {
	return nil, fmt.Errorf("not implemented")
}

func (m *mockStakingClient) DelegatorValidator(ctx context.Context, in *stakingtypes.QueryDelegatorValidatorRequest, opts ...grpc.CallOption) (*stakingtypes.QueryDelegatorValidatorResponse, error) {
	return nil, fmt.Errorf("not implemented")
}

func (m *mockStakingClient) HistoricalInfo(ctx context.Context, in *stakingtypes.QueryHistoricalInfoRequest, opts ...grpc.CallOption) (*stakingtypes.QueryHistoricalInfoResponse, error) {
	return nil, fmt.Errorf("not implemented")
}

func (m *mockStakingClient) Params(ctx context.Context, in *stakingtypes.QueryParamsRequest, opts ...grpc.CallOption) (*stakingtypes.QueryParamsResponse, error) {
	return nil, fmt.Errorf("not implemented")
}

func MockStakingClient() stakingtypes.QueryClient {
	// create the same validators as in the test
	validators := make([]stakingtypes.Validator, 10)
	totalTokens := math.ZeroInt()
	for i := range validators {
		tokens := math.NewInt(int64(i+1) * 1_000_000)
		validators[i] = stakingtypes.Validator{
			Status:          stakingtypes.Bonded,
			OperatorAddress: sdk.ValAddress(fmt.Sprintf("valoper%d", i)).String(),
			Tokens:          tokens,
		}
		totalTokens = totalTokens.Add(tokens)
	}

	return &mockStakingClient{
		validators:   validators,
		bondedTokens: totalTokens, // sum = 55_000_000
	}
}
func TestValidatorsVotingPower(t *testing.T) {
	client, err := qclient.New("localhost:9090", true)
	require.NoError(t, err)
	client = client.WithStakingClient(MockStakingClient())
	// create random validator vp array
	validators := make([]stakingtypes.Validator, 10)
	for i := range validators {
		validators[i] = stakingtypes.Validator{
			Status:          stakingtypes.Bonded,
			OperatorAddress: sdk.ValAddress(fmt.Sprintf("valoper%d", i)).String(),
			Tokens:          math.NewInt(int64(i+1) * 1_000_000),
		}
	}
	votingPower, err := client.ValidatorsVotingPower(context.Background(), validators)
	require.NoError(t, err)

	totalShare := math.LegacyZeroDec()
	for _, vp := range votingPower {
		totalShare = totalShare.Add(vp.Share)
	}
	vp, err := client.Validator(context.Background(), validators[0].OperatorAddress)
	require.NoError(t, err)
	require.Equal(t, validators[0].OperatorAddress, vp.Validator.OperatorAddress)
	require.Equal(t, validators[0].ConsensusPower(sdk.DefaultPowerReduction), vp.VotingPower)
	// shoud be around 1.81
	require.Equal(t, math.LegacyMustNewDecFromStr("0.018181818181818182"), vp.Share)

	require.Equal(t, math.LegacyOneDec(), totalShare)
}
