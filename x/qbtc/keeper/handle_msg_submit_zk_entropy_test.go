package keeper_test

import (
	"crypto/sha256"
	"testing"

	"cosmossdk.io/math"
	tmcrypto "github.com/cometbft/cometbft/proto/tendermint/crypto"
	"github.com/btcq-org/qbtc/x/qbtc/keeper"
	"github.com/btcq-org/qbtc/x/qbtc/types"
	cryptotypes "github.com/cosmos/cosmos-sdk/crypto/types"
	sdk "github.com/cosmos/cosmos-sdk/types"
	stakingtypes "github.com/cosmos/cosmos-sdk/x/staking/types"
	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSubmitZKEntropy_ValidSubmission(t *testing.T) {
	f := initFixture(t)
	msgServer := keeper.NewMsgServerImpl(f.keeper)

	// Create a validator address
	valAddr := sdk.ValAddress(f.privateKey.PubKey().Address().Bytes())
	valAddrStr, err := f.validatorAddressCodec.BytesToString(valAddr)
	require.NoError(t, err)

	// Mock validator lookup
	mockValidator := &mockValidatorI{
		status: stakingtypes.Bonded,
	}
	f.stakingKeeper.EXPECT().Validator(gomock.Any(), gomock.Any()).Return(mockValidator, nil)

	// Mock iterate to return 4 bonded validators (threshold)
	f.stakingKeeper.EXPECT().IterateBondedValidatorsByPower(gomock.Any(), gomock.Any()).DoAndReturn(
		func(ctx interface{}, fn func(int64, stakingtypes.ValidatorI) bool) error {
			for i := int64(0); i < 4; i++ {
				if fn(i, mockValidator) {
					break
				}
			}
			return nil
		},
	)

	// Generate entropy and commitment
	entropy := make([]byte, 32)
	for i := range entropy {
		entropy[i] = byte(i)
	}
	commitment := computeCommitment(entropy, valAddrStr)

	// Submit entropy
	msg := &types.MsgSubmitZKEntropy{
		Validator:  valAddrStr,
		Entropy:    entropy,
		Commitment: commitment,
	}

	resp, err := msgServer.SubmitZKEntropy(f.ctx, msg)
	require.NoError(t, err)
	assert.NotNil(t, resp)
	assert.Equal(t, uint64(1), resp.SubmissionCount)
}

func TestSubmitZKEntropy_InvalidCommitment(t *testing.T) {
	f := initFixture(t)
	msgServer := keeper.NewMsgServerImpl(f.keeper)

	// Create a validator address
	valAddr := sdk.ValAddress(f.privateKey.PubKey().Address().Bytes())
	valAddrStr, err := f.validatorAddressCodec.BytesToString(valAddr)
	require.NoError(t, err)

	// Mock validator lookup
	mockValidator := &mockValidatorI{
		status: stakingtypes.Bonded,
	}
	f.stakingKeeper.EXPECT().Validator(gomock.Any(), gomock.Any()).Return(mockValidator, nil)

	// Mock iterate to return 4 bonded validators
	f.stakingKeeper.EXPECT().IterateBondedValidatorsByPower(gomock.Any(), gomock.Any()).DoAndReturn(
		func(ctx interface{}, fn func(int64, stakingtypes.ValidatorI) bool) error {
			for i := int64(0); i < 4; i++ {
				if fn(i, mockValidator) {
					break
				}
			}
			return nil
		},
	)

	// Generate entropy with wrong commitment
	entropy := make([]byte, 32)
	for i := range entropy {
		entropy[i] = byte(i)
	}
	wrongCommitment := make([]byte, 32) // All zeros - doesn't match

	// Submit entropy with wrong commitment
	msg := &types.MsgSubmitZKEntropy{
		Validator:  valAddrStr,
		Entropy:    entropy,
		Commitment: wrongCommitment,
	}

	_, err = msgServer.SubmitZKEntropy(f.ctx, msg)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "commitment does not match")
}

func TestSubmitZKEntropy_NotBondedValidator(t *testing.T) {
	f := initFixture(t)
	msgServer := keeper.NewMsgServerImpl(f.keeper)

	// Create a validator address
	valAddr := sdk.ValAddress(f.privateKey.PubKey().Address().Bytes())
	valAddrStr, err := f.validatorAddressCodec.BytesToString(valAddr)
	require.NoError(t, err)

	// Mock validator lookup - not bonded
	mockValidator := &mockValidatorI{
		status: stakingtypes.Unbonded,
	}
	f.stakingKeeper.EXPECT().Validator(gomock.Any(), gomock.Any()).Return(mockValidator, nil)

	// Generate entropy
	entropy := make([]byte, 32)
	commitment := computeCommitment(entropy, valAddrStr)

	// Submit entropy
	msg := &types.MsgSubmitZKEntropy{
		Validator:  valAddrStr,
		Entropy:    entropy,
		Commitment: commitment,
	}

	_, err = msgServer.SubmitZKEntropy(f.ctx, msg)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "validator is not bonded")
}

func TestSubmitZKEntropy_DuplicateSubmission(t *testing.T) {
	f := initFixture(t)
	msgServer := keeper.NewMsgServerImpl(f.keeper)

	// Create a validator address
	valAddr := sdk.ValAddress(f.privateKey.PubKey().Address().Bytes())
	valAddrStr, err := f.validatorAddressCodec.BytesToString(valAddr)
	require.NoError(t, err)

	// Mock validator lookup
	mockValidator := &mockValidatorI{
		status: stakingtypes.Bonded,
	}
	f.stakingKeeper.EXPECT().Validator(gomock.Any(), gomock.Any()).Return(mockValidator, nil).Times(2)

	// Mock iterate to return 4 bonded validators
	f.stakingKeeper.EXPECT().IterateBondedValidatorsByPower(gomock.Any(), gomock.Any()).DoAndReturn(
		func(ctx interface{}, fn func(int64, stakingtypes.ValidatorI) bool) error {
			for i := int64(0); i < 4; i++ {
				if fn(i, mockValidator) {
					break
				}
			}
			return nil
		},
	).Times(1)

	// Generate entropy
	entropy := make([]byte, 32)
	for i := range entropy {
		entropy[i] = byte(i)
	}
	commitment := computeCommitment(entropy, valAddrStr)

	// Submit entropy first time
	msg := &types.MsgSubmitZKEntropy{
		Validator:  valAddrStr,
		Entropy:    entropy,
		Commitment: commitment,
	}

	_, err = msgServer.SubmitZKEntropy(f.ctx, msg)
	require.NoError(t, err)

	// Submit entropy second time - should fail
	_, err = msgServer.SubmitZKEntropy(f.ctx, msg)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "already submitted")
}

func TestCombineEntropy(t *testing.T) {
	// Test that XOR combination preserves randomness
	// If any input is random, output should be unpredictable

	submissions := []types.ZKEntropySubmission{
		{
			Validator: "val1",
			Entropy:   []byte{0xFF, 0x00, 0xFF, 0x00, 0xFF, 0x00, 0xFF, 0x00, 0xFF, 0x00, 0xFF, 0x00, 0xFF, 0x00, 0xFF, 0x00, 0xFF, 0x00, 0xFF, 0x00, 0xFF, 0x00, 0xFF, 0x00, 0xFF, 0x00, 0xFF, 0x00, 0xFF, 0x00, 0xFF, 0x00},
		},
		{
			Validator: "val2",
			Entropy:   []byte{0x00, 0xFF, 0x00, 0xFF, 0x00, 0xFF, 0x00, 0xFF, 0x00, 0xFF, 0x00, 0xFF, 0x00, 0xFF, 0x00, 0xFF, 0x00, 0xFF, 0x00, 0xFF, 0x00, 0xFF, 0x00, 0xFF, 0x00, 0xFF, 0x00, 0xFF, 0x00, 0xFF, 0x00, 0xFF},
		},
		{
			Validator: "val3",
			Entropy:   make([]byte, 32), // All zeros - malicious
		},
		{
			Validator: "val4",
			Entropy:   []byte{0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0, 0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0, 0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0, 0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0},
		},
	}

	// Even with one malicious zero-submission, the combined result should be non-zero
	combined := combineEntropyForTest(submissions)
	require.NotNil(t, combined)
	require.Len(t, combined, 32)

	// The combined entropy should not be predictable without knowing all inputs
	// This test just verifies it's non-zero
	allZero := true
	for _, b := range combined {
		if b != 0 {
			allZero = false
			break
		}
	}
	assert.False(t, allZero, "combined entropy should not be all zeros")
}

// Helper to compute commitment
func computeCommitment(entropy []byte, validator string) []byte {
	hasher := sha256.New()
	hasher.Write(entropy)
	hasher.Write([]byte(validator))
	return hasher.Sum(nil)
}

// combineEntropyForTest mirrors the combineEntropy function for testing
func combineEntropyForTest(submissions []types.ZKEntropySubmission) []byte {
	if len(submissions) == 0 {
		return nil
	}

	result := make([]byte, len(submissions[0].Entropy))
	copy(result, submissions[0].Entropy)

	for i := 1; i < len(submissions); i++ {
		entropy := submissions[i].Entropy
		for j := 0; j < len(result) && j < len(entropy); j++ {
			result[j] ^= entropy[j]
		}
	}

	hasher := sha256.New()
	hasher.Write([]byte("qbtc-zk-entropy-v1"))
	hasher.Write(result)
	for _, sub := range submissions {
		hasher.Write([]byte(sub.Validator))
	}

	return hasher.Sum(nil)
}

// mockValidatorI implements stakingtypes.ValidatorI for testing
type mockValidatorI struct {
	status stakingtypes.BondStatus
}

func (m *mockValidatorI) GetStatus() stakingtypes.BondStatus            { return m.status }
func (m *mockValidatorI) IsBonded() bool                                { return m.status == stakingtypes.Bonded }
func (m *mockValidatorI) IsUnbonded() bool                              { return m.status == stakingtypes.Unbonded }
func (m *mockValidatorI) IsUnbonding() bool                             { return m.status == stakingtypes.Unbonding }
func (m *mockValidatorI) GetMoniker() string                            { return "test" }
func (m *mockValidatorI) IsJailed() bool                                { return false }
func (m *mockValidatorI) GetOperator() string                           { return "" }
func (m *mockValidatorI) ConsPubKey() (cryptotypes.PubKey, error)       { return nil, nil }
func (m *mockValidatorI) TmConsPublicKey() (tmcrypto.PublicKey, error)  { return tmcrypto.PublicKey{}, nil }
func (m *mockValidatorI) GetConsAddr() ([]byte, error)                  { return nil, nil }
func (m *mockValidatorI) GetTokens() math.Int                           { return math.NewInt(1000000) }
func (m *mockValidatorI) GetBondedTokens() math.Int                     { return math.NewInt(1000000) }
func (m *mockValidatorI) GetConsensusPower(math.Int) int64              { return 1 }
func (m *mockValidatorI) GetCommission() math.LegacyDec                 { return math.LegacyNewDec(0) }
func (m *mockValidatorI) GetMinSelfDelegation() math.Int                { return math.NewInt(0) }
func (m *mockValidatorI) GetDelegatorShares() math.LegacyDec            { return math.LegacyNewDec(1000000) }
func (m *mockValidatorI) TokensFromShares(math.LegacyDec) math.LegacyDec { return math.LegacyNewDec(0) }
func (m *mockValidatorI) TokensFromSharesTruncated(math.LegacyDec) math.LegacyDec { return math.LegacyNewDec(0) }
func (m *mockValidatorI) TokensFromSharesRoundUp(math.LegacyDec) math.LegacyDec { return math.LegacyNewDec(0) }
func (m *mockValidatorI) SharesFromTokens(math.Int) (math.LegacyDec, error) { return math.LegacyNewDec(0), nil }
func (m *mockValidatorI) SharesFromTokensTruncated(math.Int) (math.LegacyDec, error) { return math.LegacyNewDec(0), nil }

