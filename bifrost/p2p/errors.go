package p2p

import "errors"

var (
	ErrNetworkAlreadyStarted = errors.New("network already started")
	ErrInvalidKey            = errors.New("invalid key")
)
