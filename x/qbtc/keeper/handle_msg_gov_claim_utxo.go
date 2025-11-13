package keeper

import (
	"context"

	"github.com/btcq-org/qbtc/x/qbtc/types"
	sdkerror "github.com/cosmos/cosmos-sdk/types/errors"
)

func (s *msgServer) GovClaimUTXO(ctx context.Context, msg *types.MsgGovClaimUTXO) (*types.MsgEmpty, error) {
	if msg.Authority != s.k.GetAuthority() {
		return nil, sdkerror.ErrUnauthorized.Wrap("unauthorized")
	}

	for _, utxo := range msg.Utxos {
		if err := s.k.ClaimUTXO(ctx, utxo.Txid, utxo.Vout); err != nil {
			return nil, err
		}
	}
	return &types.MsgEmpty{}, nil
}
