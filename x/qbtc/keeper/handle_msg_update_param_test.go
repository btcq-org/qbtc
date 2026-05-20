package keeper_test

import (
	"testing"

	"github.com/btcq-org/qbtc/constants"
	"github.com/btcq-org/qbtc/x/qbtc/keeper"
	"github.com/btcq-org/qbtc/x/qbtc/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_msgServer_UpdateParam(t *testing.T) {
	tests := []struct {
		name    string
		msg     *types.MsgUpdateParam
		want    *types.MsgEmpty
		wantErr bool
	}{
		{
			name: "valid message - unauthorized",
			msg: &types.MsgUpdateParam{
				Authority: "qbtc1validaddressxxxxxxxxxxxxxxxx",
				Key:       constants.EmissionCurve.String(),
				Value:     42,
			},
			want:    nil,
			wantErr: true,
		},
		{
			name: "invalid message - authority empty",
			msg: &types.MsgUpdateParam{
				Authority: "",
				Key:       constants.EmissionCurve.String(),
				Value:     42,
			},
			want:    nil,
			wantErr: true,
		},
		{
			name: "invalid message - key empty",
			msg: &types.MsgUpdateParam{
				Authority: "gov",
				Key:       "",
				Value:     42,
			},
			want:    nil,
			wantErr: true,
		},
		{
			name: "invalid message - value negative",
			msg: &types.MsgUpdateParam{
				Authority: "gov",
				Key:       constants.EmissionCurve.String(),
				Value:     -1,
			},
			want:    nil,
			wantErr: true,
		},
		{
			name: "invalid message - unknown key",
			msg: &types.MsgUpdateParam{
				Authority: "gov",
				Key:       "test_param",
				Value:     42,
			},
			want:    nil,
			wantErr: true,
		},
		{
			name: "valid int64 param",
			msg: &types.MsgUpdateParam{
				Authority: "gov",
				Key:       constants.EmissionCurve.String(),
				Value:     42,
			},
			want:    &types.MsgEmpty{},
			wantErr: false,
		},
		{
			name: "valid DevFundAddress - set to empty (clear)",
			msg: &types.MsgUpdateParam{
				Authority:   "gov",
				Key:         types.DevFundAddressKey,
				StringValue: "",
			},
			want:    &types.MsgEmpty{},
			wantErr: false,
		},
		{
			name: "invalid DevFundAddress - bad bech32",
			msg: &types.MsgUpdateParam{
				Authority:   "gov",
				Key:         types.DevFundAddressKey,
				StringValue: "not-a-valid-address",
			},
			want:    nil,
			wantErr: true,
		},
		{
			name: "valid MarketingFundAddress - set to empty (clear)",
			msg: &types.MsgUpdateParam{
				Authority:   "gov",
				Key:         types.MarketingFundAddressKey,
				StringValue: "",
			},
			want:    &types.MsgEmpty{},
			wantErr: false,
		},
		{
			name: "invalid MarketingFundAddress - bad bech32",
			msg: &types.MsgUpdateParam{
				Authority:   "gov",
				Key:         types.MarketingFundAddressKey,
				StringValue: "not-a-valid-address",
			},
			want:    nil,
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(st *testing.T) {
			f := initFixture(st)
			assert.NotNil(st, f)

			server := keeper.NewMsgServerImpl(f.keeper)

			got, gotErr := server.UpdateParam(f.ctx, tt.msg)
			if gotErr != nil {
				if !tt.wantErr {
					t.Errorf("UpdateParam() failed: %v", gotErr)
				}
				return
			}
			if tt.wantErr {
				t.Fatal("UpdateParam() succeeded unexpectedly")
			}
			assert.Equal(st, tt.want, got)
		})
	}
}

func Test_msgServer_UpdateParam_StringParamPersisted(t *testing.T) {
	f := initFixture(t)
	server := keeper.NewMsgServerImpl(f.keeper)

	// Generate a valid qbtc bech32 address from raw bytes.
	devAddrRaw := make([]byte, 20)
	copy(devAddrRaw, []byte("dev_fund_address_000"))
	devAddrStr, err := f.addressCodec.BytesToString(devAddrRaw)
	require.NoError(t, err)

	// Set DevFundAddress.
	_, err = server.UpdateParam(f.ctx, &types.MsgUpdateParam{
		Authority:   "gov",
		Key:         types.DevFundAddressKey,
		StringValue: devAddrStr,
	})
	require.NoError(t, err)

	// Verify it was stored.
	got := f.keeper.GetStringParam(f.ctx, types.DevFundAddressKey)
	assert.Equal(t, devAddrStr, got)

	// Clear it.
	_, err = server.UpdateParam(f.ctx, &types.MsgUpdateParam{
		Authority:   "gov",
		Key:         types.DevFundAddressKey,
		StringValue: "",
	})
	require.NoError(t, err)
	got = f.keeper.GetStringParam(f.ctx, types.DevFundAddressKey)
	assert.Equal(t, "", got)
}
