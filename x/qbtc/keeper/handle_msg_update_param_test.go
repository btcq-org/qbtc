package keeper_test

import (
	"testing"

	"github.com/btcq-org/qbtc/x/qbtc/keeper"
	"github.com/btcq-org/qbtc/x/qbtc/types"
	"github.com/stretchr/testify/assert"
)

func Test_msgServer_UpdateParam(t *testing.T) {
	tests := []struct {
		name string // description of this test case
		// Named input parameters for target function.
		msg     *types.MsgUpdateParam
		want    *types.MsgEmpty
		wantErr bool
	}{
		{
			name: "valid message - unauthorized",
			msg: &types.MsgUpdateParam{
				Authority: "qbtc1validaddressxxxxxxxxxxxxxxxx",
				Key:       "test_param",
				Value:     42,
			},
			want:    nil,
			wantErr: true,
		},
		{
			name: "invalid message - authority empty",
			msg: &types.MsgUpdateParam{
				Authority: "",
				Key:       "test_param",
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
				Key:       "test_param",
				Value:     -1,
			},
			want:    nil,
			wantErr: true,
		},
		{
			name: "valid message",
			msg: &types.MsgUpdateParam{
				Authority: "gov",
				Key:       "test_param",
				Value:     42,
			},
			want:    &types.MsgEmpty{},
			wantErr: false,
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
