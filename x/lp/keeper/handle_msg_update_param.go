package keeper

import (
	"context"

	sdk "github.com/cosmos/cosmos-sdk/types"

	"github.com/btcq-org/qbtc/x/lp/types"
)

func (s *msgServer) UpdateParam(
	ctx context.Context,
	msg *types.MsgUpdateParam,
) (*types.MsgUpdateParamResponse, error) {
	if err := msg.ValidateBasic(); err != nil {
		return nil, err
	}
	if msg.Authority != s.k.GetAuthority() {
		return nil, types.ErrInvalidAuthority.Wrapf(
			"expected %s, got %s", s.k.GetAuthority(), msg.Authority)
	}
	if err := s.k.SetParam(ctx, msg.Key, msg.Value); err != nil {
		return nil, err
	}
	sdk.UnwrapSDKContext(ctx).EventManager().EmitEvent(
		sdk.NewEvent("lp_param_updated",
			sdk.NewAttribute("key", msg.Key),
			sdk.NewAttribute("value", intString(msg.Value)),
		),
	)
	return &types.MsgUpdateParamResponse{}, nil
}
