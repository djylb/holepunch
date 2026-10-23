package holepunch

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/djylb/holepunch/internal/controlwire"
	"github.com/djylb/holepunch/internal/life"
	"github.com/djylb/holepunch/protocol"
)

func TestErrorFormatAndAs(t *testing.T) {
	inner := errors.New("boom")
	e := &Error{Reason: protocol.ReasonCandidateTimeout, Phase: protocol.PhasePunching, Detail: "icmp_unreachable", Err: inner}
	if got := e.Error(); got != "holepunch: candidate_timeout in punching: icmp_unreachable" {
		t.Fatalf("Error() = %q", got)
	}
	if !errors.Is(e, inner) {
		t.Fatal("Unwrap")
	}
	var target *Error
	if !errors.As(fmt.Errorf("wrap: %w", e), &target) || !errors.Is(target, e) || target.Reason != protocol.ReasonCandidateTimeout {
		t.Fatal("As")
	}
	if got := (&Error{Reason: protocol.ReasonCanceled, Phase: protocol.PhaseCreated}).Error(); got != "holepunch: canceled in created" {
		t.Fatalf("no detail: %q", got)
	}
}

// TestClassify covers the causes that are not punch evidence.
func TestClassify(t *testing.T) {
	bg := context.Background()
	canceled, cancel := context.WithCancel(bg)
	cancel()
	pe := life.Safe("worker", func() { panic(context.Canceled) })
	cases := []struct {
		name   string
		ctx    context.Context
		cause  error
		reason protocol.Reason
		detail string
	}{
		{"panic first even when it wraps Canceled", canceled, pe, protocol.ReasonInternal, "panic:worker"},
		{"caller canceled", canceled, errors.New("io"), protocol.ReasonCanceled, ""},
		{"structured", bg, fail(protocol.ReasonControlTimeout, "go_wait", nil), protocol.ReasonControlTimeout, "go_wait"},
		{"wire version", bg, controlwire.ErrVersion, protocol.ReasonControlVersionMismatch, "frame_version"},
		{"wire flood", bg, controlwire.ErrFlood, protocol.ReasonProtocolViolation, "control_flood"},
		{"deadline unsupported", bg, controlwire.ErrDeadlineUnsupported, protocol.ReasonInvalidArgument, "deadline_unsupported"},
		{"bare canceled", bg, context.Canceled, protocol.ReasonCanceled, ""},
		{"the runtime's own panic failure keeps its detail", bg,
			ctlCause(life.Safe("ctl-read:intercept", func() { panic("x") })), protocol.ReasonInternal, "panic:ctl-read"},
		{"unknown", bg, errors.New("weird"), protocol.ReasonInternal, "unclassified"},
	}
	for _, c := range cases {
		f := classify(c.ctx, c.cause)
		if f.reason != c.reason || f.detail != c.detail {
			t.Errorf("%s: got %s/%s want %s/%s", c.name, f.reason, f.detail, c.reason, c.detail)
		}
	}
	if fail(protocol.ReasonInternal, "", nil).Error() != "internal" || fail(protocol.ReasonInternal, "x", nil).Error() != "internal: x" {
		t.Fatal("failure text")
	}
}

// TestAttributePunch walks the attribution of a punch that ended without a
// confirmation.
func TestAttributePunch(t *testing.T) {
	base := punchEvidence{role: protocol.RoleInitiator, sent: 40, fired: true}
	with := func(f func(e *punchEvidence)) punchEvidence { e := base; f(&e); return e }
	cases := []struct {
		row    string
		ev     punchEvidence
		reason protocol.Reason
		detail string
	}{
		{"10a", with(func(e *punchEvidence) { e.udpBlocked = true; e.rxVerified = 3 }), protocol.ReasonUDPBlocked, "send_failed"},
		{"12a", with(func(e *punchEvidence) { e.budgetUsedPct = 100; e.peerSeenUs = true }), protocol.ReasonPacketBudgetExceeded, ""},
		{"12b", with(func(e *punchEvidence) { e.tokenMismatch = 3 }), protocol.ReasonTokenMismatch, ""},
		{"12c", with(func(e *punchEvidence) { e.peerSeenUs = true }), protocol.ReasonOneWayUDPOnly, "peer_hears_us"},
		{"12c responder", with(func(e *punchEvidence) { e.role = protocol.RoleResponder; e.peerSeenUs = true }), protocol.ReasonOneWayUDPOnly, "peer_hears_us"},
		{"12d", with(func(e *punchEvidence) { e.rxVerified = 4; e.seenFrom = 1 }), protocol.ReasonOneWayUDPOnly, "we_hear_peer"},
		{"12d responder", with(func(e *punchEvidence) { e.role = protocol.RoleResponder; e.rxVerified = 4; e.seenFrom = 1 }), protocol.ReasonOneWayUDPOnly, "we_hear_peer"},
		{"12e", with(func(e *punchEvidence) { e.rxVerified = 4; e.seenFrom = 1; e.hit = true; e.peerSeenUs = true }), protocol.ReasonCandidateTimeout, ""},
		{"12f", with(func(e *punchEvidence) { e.fired = false }), protocol.ReasonNotSynchronized, ""},
		{"12g", with(func(e *punchEvidence) { e.bothRND = true; e.birthdayRan = true }), protocol.ReasonHardSymmetricRandom, ""},
		{"12g needs birthday", with(func(e *punchEvidence) { e.bothRND = true }), protocol.ReasonCandidateTimeout, ""},
		{"12h icmp", with(func(e *punchEvidence) { e.icmpUnreach = 60 }), protocol.ReasonCandidateTimeout, "icmp_unreachable"},
		{"12h", base, protocol.ReasonCandidateTimeout, ""},
	}
	for _, c := range cases {
		r, d := attributePunch(c.ev)
		if r != c.reason || d != c.detail {
			t.Errorf("row %s: got %s/%q want %s/%q", c.row, r, d, c.reason, c.detail)
		}
	}
}

func TestCtlCause(t *testing.T) {
	pe := life.Safe("ctl-read", func() { panic("x") })
	cases := []struct {
		err    error
		reason protocol.Reason
	}{
		{pe, protocol.ReasonInternal},
		{controlwire.ErrReleased, protocol.ReasonInternal},
		{fmt.Errorf("read: %w", errClosedForTest()), protocol.ReasonCanceled},
		{controlwire.ErrBadMagic, protocol.ReasonProtocolViolation},
		{errors.New("EOF"), protocol.ReasonControlInterrupted},
	}
	for _, c := range cases {
		if f := ctlCause(c.err); f.reason != c.reason {
			t.Errorf("%v: %s want %s", c.err, f.reason, c.reason)
		}
	}
	if f := ctlCause(errClosedForTest()); !errors.Is(f.err, ErrClosed) {
		t.Fatal("closed control is ErrClosed")
	}
	// A panic names the side of the link that panicked.
	for where, detail := range map[string]string{
		"ctl-read": "panic:ctl-read", "ctl-read:intercept": "panic:ctl-read",
		"ctl-write": "panic:ctl-write", "ctl-write:build punch_ready": "panic:ctl-write",
	} {
		if f := ctlCause(life.Safe(where, func() { panic("x") })); f.reason != protocol.ReasonInternal || f.detail != detail {
			t.Errorf("%s: %s/%q want internal/%q", where, f.reason, f.detail, detail)
		}
	}
}

// panicAs is a caller's error whose As method panics.
type panicAs struct{}

func (panicAs) Error() string { return "caller cause" }
func (panicAs) As(_ any) bool { panic("caller As") }

// The caller's cancellation cause is the caller's code: a panic in its
// methods while the cause is classified fails the session as internal, and
// the cleanup still runs to the end — control returned, sockets closed.
func TestCallerCausePanicsInClassify(t *testing.T) {
	t.Parallel()
	w := newWorld(t)
	so := newSolo(t, w, nil, nil)
	so.start(testTimeouts())
	so.report()
	so.stop(panicAs{})
	e := so.wantError(so.result(5*time.Second), protocol.ReasonInternal)
	if e.Detail != "panic:finish.classify" || e.Diagnostics == nil {
		t.Fatalf("error %+v", e)
	}
	so.checkControlReturned()
}
