package ebifrost

import (
	context "context"

	"github.com/btcq-org/qbtc/x/qbtc/types"
)

// SendBTCBlock  handles sending a BTC block to the EnshrinedBifrost.
func (eb *EnshrinedBifrost) SendBTCBlock(ctx context.Context, block *types.MsgBtcBlock) (*SendBTCBlockResponse, error) {
	if err := eb.btcBlockCache.AddItem(
		block,
		(*types.MsgBtcBlock).GetAttestations,
		(*types.MsgBtcBlock).SetAttestations,
		(*types.MsgBtcBlock).Equals,
	); err != nil {
		return nil, err
	}
	return &SendBTCBlockResponse{}, nil
}
