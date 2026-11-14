package keeper_test

import (
	"context"
	"errors"
	"math"
	"testing"

	errorsmod "cosmossdk.io/errors"
	sdkmath "cosmossdk.io/math"
	"github.com/btcq-org/qbtc/constants"
	"github.com/btcq-org/qbtc/x/qbtc/keeper"
	"github.com/btcq-org/qbtc/x/qbtc/types"
	sdk "github.com/cosmos/cosmos-sdk/types"
	sdkerrors "github.com/cosmos/cosmos-sdk/types/errors"
	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/require"
)

var referralPoolAddr = sdk.AccAddress([]byte("referral-pool-addr00"))

// referralPool is a fake referral module account: GetBalance reads balance and
// payouts debit it and record what each address received.
type referralPool struct {
	balance  sdkmath.Int
	received map[string]sdkmath.Int
	sendErr  error
}

func newReferralPool(f *fixture, balance int64) *referralPool {
	pool := &referralPool{balance: sdkmath.NewInt(balance), received: map[string]sdkmath.Int{}}
	f.authKeeper.EXPECT().GetModuleAddress(types.ReferralModuleName).Return(referralPoolAddr).AnyTimes()
	f.bankKeeper.EXPECT().GetBalance(gomock.Any(), referralPoolAddr, sdk.DefaultBondDenom).DoAndReturn(
		func(context.Context, sdk.AccAddress, string) sdk.Coin {
			return sdk.NewCoin(sdk.DefaultBondDenom, pool.balance)
		}).AnyTimes()
	f.bankKeeper.EXPECT().SendCoinsFromModuleToAccount(gomock.Any(), types.ReferralModuleName, gomock.Any(), gomock.Any()).DoAndReturn(
		func(_ context.Context, _ string, to sdk.AccAddress, coins sdk.Coins) error {
			if pool.sendErr != nil {
				return pool.sendErr
			}
			amount := coins.AmountOf(sdk.DefaultBondDenom)
			if amount.GT(pool.balance) {
				return errors.New("insufficient funds")
			}
			pool.balance = pool.balance.Sub(amount)
			prev, ok := pool.received[to.String()]
			if !ok {
				prev = sdkmath.ZeroInt()
			}
			pool.received[to.String()] = prev.Add(amount)
			return nil
		}).AnyTimes()
	return pool
}

func (p *referralPool) receivedBy(addr sdk.AccAddress) int64 {
	if v, ok := p.received[addr.String()]; ok {
		return v.Int64()
	}
	return 0
}

func setRewardBps(t *testing.T, f *fixture, referrerBps, refereeBps int64) {
	t.Helper()
	require.NoError(t, f.keeper.ConstOverrides.Set(f.ctx, constants.ReferrerRewardBps.String(), referrerBps))
	require.NoError(t, f.keeper.ConstOverrides.Set(f.ctx, constants.RefereeRewardBps.String(), refereeBps))
}

func referralEvents(ctx sdk.Context) []sdk.Event {
	var events []sdk.Event
	for _, e := range ctx.EventManager().Events() {
		if e.Type == types.EventTypeReferralReward {
			events = append(events, e)
		}
	}
	return events
}

func TestReferralReward(t *testing.T) {
	tests := []struct {
		name   string
		amount uint64
		bps    int64
		want   uint64
	}{
		{"zero bps", 1_000_000, 0, 0},
		{"negative bps", 1_000_000, -5, 0},
		{"five percent", 1_000_000, 500, 50_000},
		{"rounds down", 19, 500, 0},
		{"full amount", 1_000_000, constants.MaxRewardBps, 1_000_000},
		{"capped at 100%", 1_000_000, constants.MaxRewardBps + 1, 1_000_000},
		{"no uint64 overflow", math.MaxUint64, constants.MaxRewardBps, math.MaxUint64},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, tc.want, keeper.ReferralRewardForTesting(tc.amount, tc.bps).Uint64())
		})
	}
}

func TestApplyReferral(t *testing.T) {
	referrer := sdk.AccAddress([]byte("referrer-address0000"))
	referee := sdk.AccAddress([]byte("referee-address00000"))

	t.Run("funded pool pays the referrer", func(t *testing.T) {
		f := initFixture(t)
		ctx := sdk.UnwrapSDKContext(f.ctx).WithEventManager(sdk.NewEventManager())
		setRewardBps(t, f, 500, 0)
		pool := newReferralPool(f, 1_000_000)

		f.keeper.ApplyReferralForTesting(ctx, referrer, referee, 100_000)

		require.Equal(t, int64(5_000), pool.receivedBy(referrer))
		require.Equal(t, int64(0), pool.receivedBy(referee))
		stats, err := f.keeper.GetReferralStats(ctx, referrer)
		require.NoError(t, err)
		require.Equal(t, types.ReferralStats{
			Address:             referrer.String(),
			ReferredClaims:      1,
			ReferredAmount:      100_000,
			ReferrerRewardsPaid: 5_000,
		}, stats)
		has, err := f.keeper.ReferralStats.Has(ctx, referee)
		require.NoError(t, err)
		require.False(t, has, "a referee without reward gets no entry")

		events := referralEvents(ctx)
		require.Len(t, events, 1)
		attr, ok := events[0].GetAttribute(types.AttributeKeyReferrerReward)
		require.True(t, ok)
		require.Equal(t, "5000", attr.Value)
	})

	t.Run("empty pool tracks without paying", func(t *testing.T) {
		f := initFixture(t)
		ctx := sdk.UnwrapSDKContext(f.ctx).WithEventManager(sdk.NewEventManager())
		setRewardBps(t, f, 500, 100)
		pool := newReferralPool(f, 0)

		f.keeper.ApplyReferralForTesting(ctx, referrer, referee, 100_000)

		require.Empty(t, pool.received)
		stats, err := f.keeper.GetReferralStats(ctx, referrer)
		require.NoError(t, err)
		require.Equal(t, uint64(1), stats.ReferredClaims)
		require.Equal(t, uint64(100_000), stats.ReferredAmount)
		require.Zero(t, stats.ReferrerRewardsPaid)
		require.Len(t, referralEvents(ctx), 1)
	})

	t.Run("short pool pays the referrer first and owes nothing", func(t *testing.T) {
		f := initFixture(t)
		ctx := sdk.UnwrapSDKContext(f.ctx).WithEventManager(sdk.NewEventManager())
		setRewardBps(t, f, 500, 100)
		pool := newReferralPool(f, 5_500)

		f.keeper.ApplyReferralForTesting(ctx, referrer, referee, 100_000)

		require.Equal(t, int64(5_000), pool.receivedBy(referrer))
		require.Equal(t, int64(500), pool.receivedBy(referee), "referee reward is cut to what is left")
		require.True(t, pool.balance.IsZero())
		refereeStats, err := f.keeper.GetReferralStats(ctx, referee)
		require.NoError(t, err)
		require.Equal(t, uint64(500), refereeStats.RefereeRewardsPaid)

		// The next claim finds the pool empty; nothing carries over.
		f.keeper.ApplyReferralForTesting(ctx, referrer, referee, 100_000)
		require.Equal(t, int64(5_000), pool.receivedBy(referrer))
		stats, err := f.keeper.GetReferralStats(ctx, referrer)
		require.NoError(t, err)
		require.Equal(t, uint64(2), stats.ReferredClaims)
		require.Equal(t, uint64(200_000), stats.ReferredAmount)
		require.Equal(t, uint64(5_000), stats.ReferrerRewardsPaid)
	})

	t.Run("totals accumulate across claims", func(t *testing.T) {
		f := initFixture(t)
		ctx := sdk.UnwrapSDKContext(f.ctx).WithEventManager(sdk.NewEventManager())
		setRewardBps(t, f, 500, 100)
		pool := newReferralPool(f, 1_000_000)

		f.keeper.ApplyReferralForTesting(ctx, referrer, referee, 100_000)
		f.keeper.ApplyReferralForTesting(ctx, referrer, referee, 40_000)

		require.Equal(t, int64(7_000), pool.receivedBy(referrer))
		require.Equal(t, int64(1_400), pool.receivedBy(referee))
		stats, err := f.keeper.GetReferralStats(ctx, referrer)
		require.NoError(t, err)
		require.Equal(t, uint64(2), stats.ReferredClaims)
		require.Equal(t, uint64(140_000), stats.ReferredAmount)
		require.Equal(t, uint64(7_000), stats.ReferrerRewardsPaid)
	})

	t.Run("a failed payout drops the referral without failing", func(t *testing.T) {
		f := initFixture(t)
		ctx := sdk.UnwrapSDKContext(f.ctx).WithEventManager(sdk.NewEventManager())
		setRewardBps(t, f, 500, 0)
		pool := newReferralPool(f, 1_000_000)
		pool.sendErr = errors.New("send failed")

		f.keeper.ApplyReferralForTesting(ctx, referrer, referee, 100_000)

		has, err := f.keeper.ReferralStats.Has(ctx, referrer)
		require.NoError(t, err)
		require.False(t, has, "stats roll back with the failed payout")
		require.Empty(t, referralEvents(ctx))
	})
}

func TestReferralPoolMsgs(t *testing.T) {
	coins := sdk.NewCoins(sdk.NewInt64Coin(sdk.DefaultBondDenom, 1_000))

	t.Run("unauthorized", func(t *testing.T) {
		f := initFixture(t)
		server := keeper.NewMsgServerImpl(f.keeper)
		_, err := server.FundReferralPool(f.ctx, &types.MsgFundReferralPool{Authority: "someone", Amount: 1_000})
		require.ErrorContains(t, err, "unauthorized")
		_, err = server.DrainReferralPool(f.ctx, &types.MsgDrainReferralPool{Authority: "someone", Amount: 1_000})
		require.ErrorContains(t, err, "unauthorized")
	})

	t.Run("fund moves reserve to pool", func(t *testing.T) {
		f := initFixture(t)
		newReferralPool(f, 0)
		f.bankKeeper.EXPECT().SendCoinsFromModuleToModule(gomock.Any(), types.ReserveModuleName, types.ReferralModuleName, coins).Return(nil)
		_, err := keeper.NewMsgServerImpl(f.keeper).FundReferralPool(f.ctx, &types.MsgFundReferralPool{Authority: f.keeper.GetAuthority(), Amount: 1_000})
		require.NoError(t, err)
	})

	t.Run("drain moves pool to reserve", func(t *testing.T) {
		f := initFixture(t)
		newReferralPool(f, 1_000)
		f.bankKeeper.EXPECT().SendCoinsFromModuleToModule(gomock.Any(), types.ReferralModuleName, types.ReserveModuleName, coins).Return(nil)
		_, err := keeper.NewMsgServerImpl(f.keeper).DrainReferralPool(f.ctx, &types.MsgDrainReferralPool{Authority: f.keeper.GetAuthority(), Amount: 1_000})
		require.NoError(t, err)
	})

	t.Run("bank errors keep their code", func(t *testing.T) {
		for _, bankErr := range []*errorsmod.Error{sdkerrors.ErrInsufficientFunds, sdkerrors.ErrInvalidCoins} {
			f := initFixture(t)
			f.bankKeeper.EXPECT().SendCoinsFromModuleToModule(gomock.Any(), types.ReferralModuleName, types.ReserveModuleName, coins).Return(bankErr.Wrap("bank"))
			_, err := keeper.NewMsgServerImpl(f.keeper).DrainReferralPool(f.ctx, &types.MsgDrainReferralPool{Authority: f.keeper.GetAuthority(), Amount: 1_000})
			require.ErrorIs(t, err, bankErr)
		}
	})
}

func TestReferralQueries(t *testing.T) {
	f := initFixture(t)
	setRewardBps(t, f, 300, 50)
	newReferralPool(f, 12_345)
	addr := sdk.AccAddress([]byte("referrer-address0000"))
	require.NoError(t, f.keeper.ReferralStats.Set(f.ctx, addr, types.ReferralStats{Address: addr.String(), ReferredClaims: 2}))

	qs := keeper.NewQueryServerImpl(f.keeper)
	pool, err := qs.ReferralPool(f.ctx, &types.QueryReferralPoolRequest{})
	require.NoError(t, err)
	require.Equal(t, &types.QueryReferralPoolResponse{Balance: 12_345, ReferrerRewardBps: 300, RefereeRewardBps: 50}, pool)

	stats, err := qs.ReferralStats(f.ctx, &types.QueryReferralStatsRequest{Address: addr.String()})
	require.NoError(t, err)
	require.Equal(t, uint64(2), stats.Stats.ReferredClaims)

	other := sdk.AccAddress([]byte("nobody-address000000"))
	stats, err = qs.ReferralStats(f.ctx, &types.QueryReferralStatsRequest{Address: other.String()})
	require.NoError(t, err)
	require.Equal(t, types.ReferralStats{Address: other.String()}, stats.Stats)

	_, err = qs.ReferralStats(f.ctx, &types.QueryReferralStatsRequest{Address: "bad"})
	require.ErrorContains(t, err, "invalid address")
}

func TestUpdateParam_RewardBpsBounds(t *testing.T) {
	f := initFixture(t)
	server := keeper.NewMsgServerImpl(f.keeper)
	for _, key := range []constants.ConstantName{constants.ReferrerRewardBps, constants.RefereeRewardBps} {
		for _, value := range []int64{0, 250, constants.MaxRewardBps} {
			_, err := server.UpdateParam(f.ctx, &types.MsgUpdateParam{Authority: f.keeper.GetAuthority(), Key: key.String(), Value: value})
			require.NoError(t, err, "%s=%d", key, value)
		}
		_, err := server.UpdateParam(f.ctx, &types.MsgUpdateParam{Authority: f.keeper.GetAuthority(), Key: key.String(), Value: constants.MaxRewardBps + 1})
		require.ErrorContains(t, err, "must be between 0 and 10000", key.String())
	}
}

func TestGenesis_ReferralStats(t *testing.T) {
	f := initFixture(t)
	addr := sdk.AccAddress([]byte("referrer-address0000"))
	stats := types.ReferralStats{Address: addr.String(), ReferredClaims: 3, ReferredAmount: 300, ReferrerRewardsPaid: 15, RefereeRewardsPaid: 2}
	utxo := types.UTXO{Txid: "ab", Vout: 1, Amount: 10, Referrer: addr.String()}
	require.NoError(t, f.keeper.InitGenesis(f.ctx, types.GenesisState{
		ReferralStats: []types.ReferralStats{stats},
		Utxos:         []*types.UTXO{&utxo},
	}))

	exported, err := f.keeper.ExportGenesis(f.ctx)
	require.NoError(t, err)
	require.Equal(t, []types.ReferralStats{stats}, exported.ReferralStats)
	require.Len(t, exported.Utxos, 1)
	require.Equal(t, addr.String(), exported.Utxos[0].Referrer)
}
