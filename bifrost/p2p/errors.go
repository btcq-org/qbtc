package p2p

import "errors"

var (
	ErrNetworkAlreadyStarted = errors.New("network already started")
	ErrInvalidKey            = errors.New("invalid key")
	ErrInvalidConfig         = errors.New("invalid config")
	ErrInvalidQBTCNodeClient = errors.New("invalid qBTC node client")
)
