package protocol

import (
	"errors"

	"github.com/djylb/holepunch/controlwire"
)

// Reason is the single failure-code enumeration of holepunch: the client's
// *Error.Reason, the coordinator's Result.Code and the wire field code of
// punch_result, round_result and punch_abort. Only the 26 names below exist on
// the wire; a receiver treats any other code as unknown (see AbortReason).
// Fine-grained information goes into a separate detail string.
//
// Reason is a plain wire code, not an error: errors carry it in a field, such
// as holepunch's *Error and *ValidationError, and are matched with errors.As.
type Reason string

// The 26 reasons.
const (
	ReasonNoCommonFamily         Reason = "no_common_family"
	ReasonNoProbeEndpoint        Reason = "no_probe_endpoint"
	ReasonProbeTimeout           Reason = "probe_timeout"
	ReasonUDPBlocked             Reason = "udp_blocked"
	ReasonLocalPortBindFailed    Reason = "local_port_bind_failed"
	ReasonControlInterrupted     Reason = "control_interrupted"
	ReasonControlTimeout         Reason = "control_timeout"
	ReasonNotSynchronized        Reason = "not_synchronized"
	ReasonOneWayUDPOnly          Reason = "one_way_udp_only"
	ReasonTokenMismatch          Reason = "token_mismatch"
	ReasonCandidateTimeout       Reason = "candidate_timeout"
	ReasonHardSymmetricRandom    Reason = "hard_symmetric_random"
	ReasonPacketBudgetExceeded   Reason = "packet_budget_exceeded"
	ReasonHandoverTimeout        Reason = "handover_timeout"
	ReasonControlVersionMismatch Reason = "control_version_mismatch"
	ReasonProtocolViolation      Reason = "protocol_violation"
	ReasonInvalidArgument        Reason = "invalid_argument"
	ReasonPeerOffline            Reason = "peer_offline"
	ReasonSessionExpired         Reason = "session_expired"
	ReasonServerBusy             Reason = "server_busy"
	ReasonServerShutdown         Reason = "server_shutdown"
	ReasonTransportMismatch      Reason = "transport_mismatch"
	ReasonAbortedByPeer          Reason = "aborted_by_peer"
	ReasonAbortedByServer        Reason = "aborted_by_server"
	ReasonCanceled               Reason = "canceled"
	ReasonInternal               Reason = "internal"
)

// Reasons returns the 26 reasons in their canonical order.
func Reasons() []Reason {
	return []Reason{
		ReasonNoCommonFamily, ReasonNoProbeEndpoint, ReasonProbeTimeout, ReasonUDPBlocked,
		ReasonLocalPortBindFailed, ReasonControlInterrupted, ReasonControlTimeout, ReasonNotSynchronized,
		ReasonOneWayUDPOnly, ReasonTokenMismatch, ReasonCandidateTimeout, ReasonHardSymmetricRandom,
		ReasonPacketBudgetExceeded, ReasonHandoverTimeout, ReasonControlVersionMismatch, ReasonProtocolViolation,
		ReasonInvalidArgument, ReasonPeerOffline, ReasonSessionExpired, ReasonServerBusy,
		ReasonServerShutdown, ReasonTransportMismatch, ReasonAbortedByPeer, ReasonAbortedByServer,
		ReasonCanceled, ReasonInternal,
	}
}

// Known reports whether r is one of the 26 reasons.
func (r Reason) Known() bool { return r.Class() != ClassNone }

// ReasonClass groups reasons for retry decisions: none (unknown reason) |
// fatal | transient | nat_hard | canceled. It is the only retry hint holepunch
// gives; a caller builds its own retry schedule on top of it.
type ReasonClass uint8

// Reason classes.
const (
	ClassNone ReasonClass = iota
	ClassFatal
	ClassTransient
	ClassNATHard
	ClassCanceled
)

func reasonClassNames() [5]string {
	return [5]string{"none", "fatal", "transient", "nat_hard", "canceled"}
}

// String returns the wire name of c.
//
//goland:noinspection GoMixedReceiverTypes
func (c ReasonClass) String() string { n := reasonClassNames(); return enumString(n[:], uint8(c)) }

// MarshalText encodes c as its name; an out-of-range value is an error.
//
//goland:noinspection GoMixedReceiverTypes
func (c ReasonClass) MarshalText() ([]byte, error) {
	n := reasonClassNames()
	return enumMarshal("reason class", n[:], uint8(c))
}

// UnmarshalText accepts exactly the names.
//
//goland:noinspection GoMixedReceiverTypes
func (c *ReasonClass) UnmarshalText(b []byte) error {
	n := reasonClassNames()
	return enumParse(c, "reason class", n[:], b)
}

// Class is r's class; ClassNone for an unknown reason.
func (r Reason) Class() ReasonClass {
	switch r {
	case ReasonNoCommonFamily, ReasonNoProbeEndpoint, ReasonUDPBlocked, ReasonLocalPortBindFailed,
		ReasonTokenMismatch, ReasonControlVersionMismatch, ReasonProtocolViolation, ReasonInvalidArgument,
		ReasonTransportMismatch, ReasonInternal:
		return ClassFatal
	case ReasonProbeTimeout, ReasonControlInterrupted, ReasonControlTimeout, ReasonNotSynchronized,
		ReasonHandoverTimeout, ReasonPeerOffline, ReasonSessionExpired, ReasonServerBusy,
		ReasonServerShutdown, ReasonAbortedByPeer, ReasonAbortedByServer:
		return ClassTransient
	case ReasonOneWayUDPOnly, ReasonCandidateTimeout, ReasonHardSymmetricRandom, ReasonPacketBudgetExceeded:
		return ClassNATHard
	case ReasonCanceled:
		return ClassCanceled
	}
	return ClassNone
}

// AbortReason is the reason a client fails with on receiving punch_abort{by,
// code} before it confirmed: the code when it is one of the 26 reasons,
// otherwise (empty or unknown) aborted_by_<by> — aborted_by_server when the
// server aborted and aborted_by_peer when the other client did.
func AbortReason(by Role, code Reason) Reason {
	if code.Known() {
		return code
	}
	if by == RoleServer {
		return ReasonAbortedByServer
	}
	return ReasonAbortedByPeer
}

// WireReason maps an error of the wire layer — a frame-layer error of
// controlwire, a *ValidationError or ErrUnexpectedMessage — to the reason and
// detail reported for it. ok is false for any
// other error: the caller classifies it (connection errors, its own
// cancellation and timers). Callers test for *life.PanicError before calling
// WireReason, because a panic value can wrap any error.
func WireReason(err error) (r Reason, detail string, ok bool) {
	var verr *ValidationError
	switch {
	case err == nil:
		return "", "", false
	case errors.As(err, &verr):
		return verr.Reason, verr.Detail, true
	case errors.Is(err, controlwire.ErrVersion):
		return ReasonControlVersionMismatch, "frame_version", true
	case errors.Is(err, controlwire.ErrBadMagic):
		return ReasonProtocolViolation, "bad_magic", true
	case errors.Is(err, controlwire.ErrZeroType):
		return ReasonProtocolViolation, "zero_type", true
	case errors.Is(err, controlwire.ErrFrameTooLarge):
		return ReasonProtocolViolation, "frame_too_large", true
	case errors.Is(err, controlwire.ErrTooManyUnknown):
		return ReasonProtocolViolation, "unknown_frames", true
	case errors.Is(err, controlwire.ErrFlood):
		return ReasonProtocolViolation, "control_flood", true
	case errors.Is(err, ErrUnexpectedMessage):
		return ReasonProtocolViolation, "unexpected_message", true
	case errors.Is(err, controlwire.ErrDeadlineUnsupported):
		return ReasonInvalidArgument, "deadline_unsupported", true
	case errors.Is(err, controlwire.ErrNilConn):
		return ReasonInvalidArgument, "nil_control", true
	}
	return "", "", false
}
