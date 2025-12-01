package testutil

import (
	"context"
	"reflect"

	"cosmossdk.io/math"
	"github.com/btcq-org/qbtc/x/qbtc/types"
	sdk "github.com/cosmos/cosmos-sdk/types"
	stakingtypes "github.com/cosmos/cosmos-sdk/x/staking/types"
	"github.com/golang/mock/gomock"
)

type MockStakingKeeperRecorder struct {
	mock *MockStakingKeeper
}
type MockStakingKeeper struct {
	ctrl     *gomock.Controller
	recorder *MockStakingKeeperRecorder
}

var _ types.StakingKeeper = &MockStakingKeeper{}

func NewMockStakingKeeper(ctrl *gomock.Controller) *MockStakingKeeper {
	mock := &MockStakingKeeper{ctrl: ctrl}
	mock.recorder = &MockStakingKeeperRecorder{mock: mock}
	return mock
}

func (m *MockStakingKeeper) EXPECT() *MockStakingKeeperRecorder {
	return m.recorder
}

func (m *MockStakingKeeper) GetValidator(ctx context.Context, address sdk.ValAddress) (stakingtypes.Validator, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetValidator", ctx, address)
	ret0, _ := ret[0].(stakingtypes.Validator)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

func (m *MockStakingKeeper) GetAllValidators(ctx context.Context) (validators []stakingtypes.Validator, err error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetAllValidators", ctx)
	ret0, _ := ret[0].([]stakingtypes.Validator)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

func (m *MockStakingKeeper) GetBondedValidatorsByPower(ctx context.Context) ([]stakingtypes.Validator, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetBondedValidatorsByPower", ctx)
	ret0, _ := ret[0].([]stakingtypes.Validator)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

func (mr *MockStakingKeeperRecorder) GetBondedValidatorsByPower(ctx any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetBondedValidatorsByPower", reflect.TypeOf((*MockStakingKeeper)(nil).GetBondedValidatorsByPower), ctx)
}

func (m *MockStakingKeeper) GetLastTotalPower(ctx context.Context) (math.Int, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetLastTotalPower", ctx)
	ret0, _ := ret[0].(math.Int)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

func (m *MockStakingKeeper) PowerReduction(ctx context.Context) math.Int {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "PowerReduction", ctx)
	ret0, _ := ret[0].(math.Int)
	return ret0
}

func (m *MockStakingKeeper) Validator(ctx context.Context, addr sdk.ValAddress) (stakingtypes.ValidatorI, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Validator", ctx, addr)
	ret0, _ := ret[0].(stakingtypes.ValidatorI)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

func (m *MockStakingKeeper) IterateBondedValidatorsByPower(ctx context.Context, fn func(index int64, validator stakingtypes.ValidatorI) (stop bool)) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "IterateBondedValidatorsByPower", ctx, fn)
	ret0, _ := ret[0].(error)
	return ret0
}

func (mr *MockStakingKeeperRecorder) GetValidator(ctx, address any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetValidator", reflect.TypeOf((*MockStakingKeeper)(nil).GetValidator), ctx, address)
}
func (mr *MockStakingKeeperRecorder) GetAllValidators(ctx any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetAllValidators", reflect.TypeOf((*MockStakingKeeper)(nil).GetAllValidators), ctx)
}
func (mr *MockStakingKeeperRecorder) GetLastTotalPower(ctx any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetLastTotalPower", reflect.TypeOf((*MockStakingKeeper)(nil).GetLastTotalPower), ctx)
}

func (mr *MockStakingKeeperRecorder) PowerReduction(ctx any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "PowerReduction", reflect.TypeOf((*MockStakingKeeper)(nil).PowerReduction), ctx)
}

func (mr *MockStakingKeeperRecorder) Validator(ctx, addr any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Validator", reflect.TypeOf((*MockStakingKeeper)(nil).Validator), ctx, addr)
}

func (mr *MockStakingKeeperRecorder) IterateBondedValidatorsByPower(ctx, fn any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "IterateBondedValidatorsByPower", reflect.TypeOf((*MockStakingKeeper)(nil).IterateBondedValidatorsByPower), ctx, fn)
}
