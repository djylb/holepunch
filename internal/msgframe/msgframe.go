// Package msgframe converts between the control messages of package
// protocol and the frames of internal/controlwire that carry them, for the
// client runtime and coord.
package msgframe

import (
	"errors"

	"github.com/djylb/holepunch/internal/controlwire"
	"github.com/djylb/holepunch/protocol"
)

// Encode validates m and encodes it as a frame of its type (protocol.Marshal).
func Encode(m protocol.Message) (controlwire.Frame, error) {
	p, err := protocol.Marshal(m)
	if err != nil {
		return controlwire.Frame{}, err
	}
	return controlwire.Frame{Type: controlwire.Type(m.MessageType()), Payload: p}, nil
}

// Unmarshal decodes f into the message type T (protocol.Unmarshal).
func Unmarshal[T any, P interface {
	*T
	protocol.Message
}](f controlwire.Frame) (T, error) {
	return protocol.Unmarshal[T, P](protocol.MessageType(f.Type), f.Payload)
}

// Decode decodes a frame of any message type (protocol.Decode).
func Decode(f controlwire.Frame) (protocol.Message, error) {
	return protocol.Decode(protocol.MessageType(f.Type), f.Payload)
}

// AbortReason is the reason a client fails with on receiving punch_abort{by,
// code} before it confirmed: the code when it is one of the 26 reasons,
// otherwise (empty or unknown) aborted_by_<by> — aborted_by_server when the
// server aborted and aborted_by_peer when the other client did.
func AbortReason(by protocol.Role, code protocol.Reason) protocol.Reason {
	if code.Known() {
		return code
	}
	if by == protocol.RoleServer {
		return protocol.ReasonAbortedByServer
	}
	return protocol.ReasonAbortedByPeer
}

// Reason maps an error of the wire layer — a frame-layer error of
// controlwire, a *ValidationError or ErrUnexpectedMessage — to the reason and
// detail reported for it. ok is false for any
// other error: the caller classifies it (connection errors, its own
// cancellation and timers). Callers test for a recovered panic before calling
// Reason, because a panic value can wrap any error.
func Reason(err error) (r protocol.Reason, detail string, ok bool) {
	var verr *protocol.ValidationError
	switch {
	case err == nil:
		return "", "", false
	case errors.As(err, &verr):
		return verr.Reason, verr.Detail, true
	case errors.Is(err, controlwire.ErrVersion):
		return protocol.ReasonControlVersionMismatch, "frame_version", true
	case errors.Is(err, controlwire.ErrBadMagic):
		return protocol.ReasonProtocolViolation, "bad_magic", true
	case errors.Is(err, controlwire.ErrZeroType):
		return protocol.ReasonProtocolViolation, "zero_type", true
	case errors.Is(err, controlwire.ErrFrameTooLarge):
		return protocol.ReasonProtocolViolation, "frame_too_large", true
	case errors.Is(err, controlwire.ErrTooManyUnknown):
		return protocol.ReasonProtocolViolation, "unknown_frames", true
	case errors.Is(err, controlwire.ErrFlood):
		return protocol.ReasonProtocolViolation, "control_flood", true
	case errors.Is(err, protocol.ErrUnexpectedMessage):
		return protocol.ReasonProtocolViolation, "unexpected_message", true
	case errors.Is(err, controlwire.ErrDeadlineUnsupported):
		return protocol.ReasonInvalidArgument, "deadline_unsupported", true
	case errors.Is(err, controlwire.ErrNilConn):
		return protocol.ReasonInvalidArgument, "nil_control", true
	}
	return "", "", false
}
