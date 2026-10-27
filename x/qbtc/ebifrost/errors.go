package ebifrost

import "errors"

var (
	ErrAlreadyStarted = errors.New("server already started")

	// ErrNoBtcAnchor is returned by a LastProcessedFunc when the chain has no
	// Bitcoin anchor yet, so it accepts no Bitcoin block and there is nothing to
	// read.
	ErrNoBtcAnchor = errors.New("no Bitcoin anchor in chain state")
)
