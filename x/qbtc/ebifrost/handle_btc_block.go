package ebifrost

import (
	context "context"

	"cosmossdk.io/log"
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

	go eb.broadcastBtcBlockEvent(block)

	for i := 0; i < len(eb.btcBlockCache.items); i++ {
		if eb.btcBlockCache.items[i].Item.Equals(block) {
			eb.btcBlockCache.RemoveAt(i)
			break
		}
	}
	found := eb.btcBlockCache.MarkAttestationsConfirmed(
		block,
		eb.logger,
		(*types.MsgBtcBlock).Equals,
		(*types.MsgBtcBlock).GetAttestations,
		(*types.MsgBtcBlock).RemoveAttestations,
		func(block *types.MsgBtcBlock, logger log.Logger) {
			logger.Debug("Marking btc block attestations confirmed",
				"height", block.Height,
				"hash", block.Hash,
				"attestations", len(block.Attestations))
		},
	)
	if !found {
		eb.logger.Error("failed to mark btc block attestations confirmed", "height", block.Height, "hash", block.Hash)
	}

	sdkCtx := sdk.UnwrapSDKContext(ctx)
	height := sdkCtx.BlockHeight()

	eb.btcBlockCache.AddToBlock(height, block)
	eb.btcBlockCache.CleanOldBlocks(height, cachedBlocks)

}
