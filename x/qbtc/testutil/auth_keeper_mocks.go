package testutil

import (
	"context"
	"reflect"

	"cosmossdk.io/core/address"
	"github.com/btcq-org/qbtc/x/qbtc/types"
	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/golang/mock/gomock"
)

type MockAuthKeeperRecorder struct {
	mock *MockAuthKeeper
}
type MockAuthKeeper struct {
	ctrl     *gomock.Controller
	recorder *MockAuthKeeperRecorder
}

var _ types.AuthKeeper = &MockAuthKeeper{}

func NewMockAuthKeeper(ctrl *gomock.Controller) *MockAuthKeeper {
	mock := &MockAuthKeeper{ctrl: ctrl}
	mock.recorder = &MockAuthKeeperRecorder{mock: mock}
	return mock
}

func (m *MockAuthKeeper) EXPECT() *MockAuthKeeperRecorder {
	return m.recorder
}

// AddressCodec implements types.AuthKeeper.
func (m *MockAuthKeeper) AddressCodec() address.Codec {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "AddressCodec")
	ret0, _ := ret[0].(address.Codec)
	return ret0
}
func (mr *MockAuthKeeperRecorder) AddressCodec() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "AddressCodec", reflect.TypeOf((*MockAuthKeeper)(nil).AddressCodec))
}

// GetAccount implements types.AuthKeeper.
func (m *MockAuthKeeper) GetAccount(ctx context.Context, addr sdk.AccAddress) sdk.AccountI {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetAccount", ctx, addr)
	ret0, _ := ret[0].(sdk.AccountI)
	return ret0
}
func (mr *MockAuthKeeperRecorder) GetAccount(ctx, addr interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetAccount", reflect.TypeOf((*MockAuthKeeper)(nil).GetAccount), ctx, addr)
}

// GetModuleAddress implements types.AuthKeeper.
func (m *MockAuthKeeper) GetModuleAddress(name string) sdk.AccAddress {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetModuleAddress", name)
	ret0, _ := ret[0].(sdk.AccAddress)
	return ret0
}

func (mr *MockAuthKeeperRecorder) GetModuleAddress(name interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetModuleAddress", reflect.TypeOf((*MockAuthKeeper)(nil).GetModuleAddress), name)
}
