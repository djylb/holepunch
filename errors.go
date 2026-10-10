package holepunch

import (
	"context"
	"errors"
	"net/netip"
	"time"
	"unicode/utf8"

	"github.com/djylb/holepunch/internal/life"
	"github.com/djylb/holepunch/internal/plan"
	"github.com/djylb/holepunch/protocol"
)

// Error is the failure of AttachSession. Reason is one of the 26
// protocol.Reason values; match the error with errors.As and compare Reason.
type Error struct {
	Reason     protocol.Reason
	Phase      Phase
	Round      int           // the round the session was in; 0 before punching
	LastEvent  string        // the last recorded event
	AbortedBy  protocol.Role // "", initiator, responder or server: punch_abort.by
	Detail     string        // fine-grained cause, at most 256 bytes; the peer's or server's abort detail verbatim
	RetryAfter time.Duration // punch_abort.retry_after_ms (server_busy and the like)
	// Advice is the server's suggestion for the next attempt, from the
	// summary (probe_summary.plan.advice):
	// background_viable — stay on the relay and punch again in Background
	// mode — relay_only, or "" (retry as before, or failed before the
	// summary). Diagnostics.Plan.BackgroundOnly tells whether the server
	// saw this pair connect only in Background mode before.
	Advice      protocol.Advice
	Diagnostics *Diagnostics // nil when the session failed before punch_start was read
	Err         error        // the underlying error: I/O, context, decoding or *PanicError
}

// Error formats the failure as "holepunch: <reason> in <phase>: <detail>"
// (the detail part only when there is one).
func (e *Error) Error() string {
	s := "holepunch: " + string(e.Reason) + " in " + string(e.Phase)
	if e.Detail != "" {
		s += ": " + e.Detail
	}
	return s
}

// Unwrap returns the underlying error.
func (e *Error) Unwrap() error { return e.Err }

// ErrClosed is the Err of a canceled session whose control connection the
// caller closed while AttachSession was running: the library never closes that
// connection, so its closing is the caller's way to stop the session.
var ErrClosed = errors.New("holepunch: session closed")

// PanicError is a panic the library recovered, reachable through Error.Err
// (Reason internal, Detail "panic:<goroutine>"). Its textual forms never
// contain the stack, which only Stack returns, for local logs. It is the
// internal/life type, aliased like Clock.
type PanicError = life.PanicError

// maxDetail bounds Error.Detail and punch_result.detail.
const maxDetail = 256

// failure is the structured cause the runtime fails its groups with; the
// final *Error is built from it.
type failure struct {
	reason     protocol.Reason
	detail     string
	abortedBy  protocol.Role
	retryAfter time.Duration
	err        error
}

func (f *failure) Error() string {
	if f.detail != "" {
		return string(f.reason) + ": " + f.detail
	}
	return string(f.reason)
}

func (f *failure) Unwrap() error { return f.err }

func fail(r protocol.Reason, detail string, err error) *failure {
	return &failure{reason: r, detail: detail, err: err}
}

// classify turns a cause into its reason and detail. A recovered panic is
// tested first because a panic value may wrap anything; then the caller's own
// cancellation — Canceled and DeadlineExceeded alike — then the runtime's
// structured causes and the wire errors. It never returns nil.
func classify(callerCtx context.Context, cause error) *failure {
	var pe *life.PanicError
	if errors.As(cause, &pe) {
		return fail(protocol.ReasonInternal, "panic:"+pe.Where(), cause)
	}
	if callerCtx.Err() != nil {
		return fail(protocol.ReasonCanceled, "", context.Cause(callerCtx))
	}
	var f *failure
	if errors.As(cause, &f) {
		return f
	}
	if r, d, ok := protocol.WireReason(cause); ok {
		return fail(r, d, cause)
	}
	if errors.Is(cause, context.Canceled) || errors.Is(cause, context.DeadlineExceeded) {
		return fail(protocol.ReasonCanceled, "", cause)
	}
	return fail(protocol.ReasonInternal, "unclassified", cause)
}

// punchEvidence is the client's own evidence when punching ends without a
// confirmation: the input of attributePunch.
type punchEvidence struct {
	role          protocol.Role
	rxVerified    int // valid peer packets received
	seenFrom      int // distinct peer sources seen
	sent          int // initiated packets
	budgetUsedPct int
	tokenMismatch int
	icmpUnreach   int  // the highest per-round ICMP count
	hit           bool // a peer success arrived
	peerSeenUs    bool // a peer_seen about us arrived
	fired         bool // at least one round fired
	udpBlocked    bool // every socket write failed for at least 1 s while punching
	bothRND       bool // both sides' traits fall in the RND category
	birthdayRan   bool // a multi-socket random round was run
}

// tokenMismatchMin is the number of AEAD failures from a verified peer IP that
// make token_mismatch the explanation.
const tokenMismatchMin = 3

// attributePunch explains a punch that ended without a confirmation. The
// rules shared with the coordinator are plan.AttributeDetail's; the
// client-only ones (udp_blocked from local writes, the budget,
// token_mismatch, hard_symmetric_random once birthday ran) wrap it. plan's
// one-way details name the direction from the initiator's side; a client
// reports its own: peer_hears_us or we_hear_peer.
func attributePunch(ev punchEvidence) (protocol.Reason, string) {
	switch {
	case ev.udpBlocked:
		return protocol.ReasonUDPBlocked, "send_failed"
	case ev.rxVerified == 0 && ev.budgetUsedPct >= 100:
		return protocol.ReasonPacketBudgetExceeded, ""
	case ev.rxVerified == 0 && ev.tokenMismatch >= tokenMismatchMin:
		return protocol.ReasonTokenMismatch, ""
	}
	own, peer := 0, 1
	if ev.role == protocol.RoleResponder {
		own, peer = 1, 0
	}
	var pe plan.Evidence
	if ev.seenFrom > 0 || ev.rxVerified > 0 {
		pe.SeenFrom[own] = make([]netip.AddrPort, max(ev.seenFrom, 1))
	}
	pe.Hit[own] = ev.hit
	pe.PeerSeenUs[own] = ev.peerSeenUs
	pe.Sent[own] = uint32(ev.sent)
	pe.Fired[own] = ev.fired
	pe.ICMPUnreach[own] = uint16(min(ev.icmpUnreach, 0xFFFF))
	// The peer's side is unknown to this client: assume it fired and sent,
	// so that only our own evidence can make the result not_synchronized.
	pe.Sent[peer] = 1
	pe.Fired[peer] = true
	r, d := plan.AttributeDetail(pe)
	switch {
	case r == protocol.ReasonOneWayUDPOnly && ev.rxVerified > 0:
		d = "we_hear_peer"
	case r == protocol.ReasonOneWayUDPOnly:
		d = "peer_hears_us"
	case r == protocol.ReasonCandidateTimeout && d == "" && ev.rxVerified == 0 && ev.bothRND && ev.birthdayRan:
		return protocol.ReasonHardSymmetricRandom, ""
	}
	return r, d
}

// truncDetail keeps a detail within maxDetail bytes without splitting a rune.
func truncDetail(s string) string {
	if len(s) <= maxDetail {
		return s
	}
	cut := maxDetail
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut]
}
