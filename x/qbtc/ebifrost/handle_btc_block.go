package ebifrost

import (
	context "context"

	"github.com/btcq-org/qbtc/x/qbtc/types"
	sdk "github.com/cosmos/cosmos-sdk/types"
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

func (eb *EnshrinedBifrost) MarkBlockAsProcessed(ctx sdk.Context, block *types.MsgBtcBlock) {
	if eb == nil || eb.btcBlockCache == nil {
		return
	}
	eb.logger.Info("Marking BTC block as processed", "height", block.Height, "hash", block.Hash)
	go eb.broadcastBtcBlockEvent(block)

	for i := 0; i < len(eb.btcBlockCache.items); i++ {
		if eb.btcBlockCache.items[i].Item.Equals(block) {
			eb.btcBlockCache.RemoveAt(i)
			break
		}
	}

	sdkCtx := sdk.UnwrapSDKContext(ctx)
	height := sdkCtx.BlockHeight()

	eb.btcBlockCache.AddToBlock(height, block)
	eb.btcBlockCache.CleanOldBlocks(height, cachedBlocks)

}
