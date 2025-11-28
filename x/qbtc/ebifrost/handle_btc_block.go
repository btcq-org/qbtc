package ebifrost

import (
	context "context"
	"fmt"

	"github.com/btcq-org/qbtc/x/qbtc/types"
)

// SendBTCBlock  handles sending a BTC block to the EnshrinedBifrost.
func (eb *EnshrinedBifrost) SendBTCBlock(ctx context.Context, block *types.MsgBtcBlock) (*SendBTCBlockResponse, error) {
	fmt.Println("Received BTC block to send to enshrined bifrost")
	// todo: add to cache for later processing
	return &SendBTCBlockResponse{}, nil
}
