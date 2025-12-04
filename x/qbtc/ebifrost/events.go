package ebifrost

import (
	"time"

	"github.com/btcq-org/qbtc/x/qbtc/types"
)

const (
	EventTypeBtcBlockCommitted = "btc_block_committed"
)

// SubscribeToEvents subscribes to events from the EnshrinedBifrost.
func (eb *EnshrinedBifrost) SubscribeToEvents(req *SubscribeRequest, stream LocalhostBifrost_SubscribeToEventsServer) error {
	//todo: implement event subscription logic
	return nil
}

// nolint:unused
func (eb *EnshrinedBifrost) broadcastEvent(eventType string, payload []byte) {
	event := &EventNotification{
		EventType: eventType,
		Payload:   payload,
		Timestamp: time.Now().Unix(),
	}

	eb.subscribersMu.Lock()
	subscribers := eb.subscribers[eventType]
	eb.subscribersMu.Unlock()

	for _, ch := range subscribers {
		select {
		case ch <- event:
			eb.logger.Debug("Event sent to subscriber", "event", eventType)
			// Event sent successfully
		default:
			eb.logger.Error("Failed to send event to subscriber", "event", eventType)
			// Channel is full or closed, could implement cleanup here
		}
	}
}

func (eb *EnshrinedBifrost) broadcastBtcBlockEvent(tx *types.MsgBtcBlock) {
	eb.btcBlockCache.BroadcastEvent(
		tx,
		func(item *types.MsgBtcBlock) ([]byte, error) {
			return item.Marshal()
		},
		eb.broadcastEvent,
		EventTypeBtcBlockCommitted,
		eb.logger,
	)
}
