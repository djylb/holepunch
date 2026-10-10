package controlwire

import "errors"

// Errors of the frame layer. Each maps to exactly one protocol reason and
// detail; the mapping is the caller's (the client runtime and coord).
var (
	// ErrBadMagic is returned when the header does not start with 'h' 'p'
	// (protocol_violation; the peer is not speaking this protocol, so no abort
	// is sent).
	ErrBadMagic = errors.New("controlwire: bad magic")
	// ErrVersion is returned when the header's major version is not Version
	// (control_version_mismatch).
	ErrVersion = errors.New("controlwire: unsupported major version")
	// ErrZeroType is returned for frame type 0 (protocol_violation).
	ErrZeroType = errors.New("controlwire: frame type 0")
	// ErrFrameTooLarge is returned when the length exceeds the type's cap
	// (protocol_violation, detail frame_too_large).
	ErrFrameTooLarge = errors.New("controlwire: frame too large")
	// ErrReleased reports that the Conn was released; the connection belongs
	// to the caller again.
	ErrReleased = errors.New("controlwire: connection released")

	// ErrTooManyUnknown is returned when more than MaxDiscarded reserved or
	// wrong-direction frames arrived (protocol_violation).
	ErrTooManyUnknown = errors.New("controlwire: too many unknown or misdirected frames")
	// ErrFlood is returned when more frames than the per-link limit arrived
	// (protocol_violation, detail control_flood).
	ErrFlood = errors.New("controlwire: control frame flood")
	// ErrDeadlineUnsupported is returned when the connection rejects read or
	// write deadlines (invalid_argument, detail deadline_unsupported).
	ErrDeadlineUnsupported = errors.New("controlwire: connection does not support deadlines")
	// ErrNilConn is returned when NewConn is given a nil or typed-nil
	// connection (invalid_argument, detail nil_control).
	ErrNilConn = errors.New("controlwire: nil connection")
	// ErrWrongDirection is returned when this side may not send the frame
	// type (for example a client sending punch_abort).
	ErrWrongDirection = errors.New("controlwire: frame type not sent by this side")
	// ErrQueueFull is returned when the bounded write queue of the frame's
	// priority is full.
	ErrQueueFull = errors.New("controlwire: write queue full")
	// ErrDropped reports that a queued frame was discarded before it was
	// written, because the write side stopped (failure, Release or Close). It
	// wraps the cause.
	ErrDropped = errors.New("controlwire: frame dropped before write")
	// ErrUnreturnable reports that Release could not hand the connection back
	// in a clean state — a frame was cut in the middle, or a goroutine did not
	// stop in time. The library will not touch the connection again, but the
	// stream position is unknown: the caller must close it.
	ErrUnreturnable = errors.New("controlwire: connection not returnable, close it")
)
