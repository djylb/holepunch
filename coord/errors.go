package coord

import (
	"errors"
	"fmt"

	"github.com/djylb/holepunch/protocol"
)

// Errors returned by the Coordinator and Session methods. A failed Attach
// leaves the connection with the caller.
var (
	// ErrClosed is returned once the Coordinator was closed.
	ErrClosed = errors.New("coord: coordinator closed")
	// ErrBusy is returned when a session, rate or quota limit refused a new
	// session. It is a *ReasonError with Reason server_busy, shared by every
	// such return: read it, never modify it.
	ErrBusy error = &ReasonError{Reason: protocol.ReasonServerBusy}
	// ErrAlreadyAttached is returned when the role already has a control link.
	ErrAlreadyAttached = errors.New("coord: role already attached")
	// ErrSessionDone is returned when the session has ended; it no longer
	// takes links.
	ErrSessionDone = errors.New("coord: session done")
	// ErrInvalidRole is returned when the role is neither initiator nor
	// responder.
	ErrInvalidRole = errors.New("coord: invalid role")
	// ErrInvalidConn is returned when the connection is nil, a typed nil, or
	// does not support deadlines.
	ErrInvalidConn = errors.New("coord: invalid control connection")
	// ErrShutdownTimeout is returned when Close gave up waiting for sessions or
	// goroutines stuck in user code after 3 s; they are counted in
	// Stats.Stuck.
	ErrShutdownTimeout = errors.New("coord: shutdown timeout")
)

// ReasonError is a coordinator error that stands for a protocol reason:
// ErrBusy (server_busy), and the cancellation cause of the context of a
// session that did not succeed. Match a sentinel with errors.Is, or read the
// reason with errors.As.
type ReasonError struct {
	Reason protocol.Reason
	Detail string // the session end's detail, if any
}

// Error formats the error as "coord: <reason>", followed by ": <detail>"
// when there is one.
func (e *ReasonError) Error() string {
	if e.Detail == "" {
		return "coord: " + string(e.Reason)
	}
	return "coord: " + string(e.Reason) + ": " + e.Detail
}

// argumentError is the invalid_argument failure of an entry point: a
// *protocol.ValidationError whose Detail is one of the standard details
// (insecure_control, ...).
func argumentError(detail, format string, args ...any) error {
	return &protocol.ValidationError{Reason: protocol.ReasonInvalidArgument, Detail: detail, Msg: fmt.Sprintf(format, args...)}
}
