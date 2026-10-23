package holepunch

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"net"
	"net/netip"
	"syscall"
	"testing"
	"time"

	"github.com/djylb/holepunch/internal/controlwire"
	"github.com/djylb/holepunch/internal/faultconn"
	"github.com/djylb/holepunch/internal/msgframe"
	"github.com/djylb/holepunch/internal/testkit"
	"github.com/djylb/holepunch/internal/wiretype"
	"github.com/djylb/holepunch/nattest"
	"github.com/djylb/holepunch/protocol"
)

// rawFrame builds a control frame by hand, bypassing protocol validation.
func rawFrame(major, typ byte, payload []byte) []byte {
	b := []byte{'h', 'p', major, typ, 0, 0, 0, 0}
	binary.BigEndian.PutUint32(b[4:], uint32(len(payload)))
	return append(b, payload...)
}

// Start wait: no punch_start within StartWait -> control_timeout, no
// diagnostics.
func TestStartWaitTimeout(t *testing.T) {
	t.Parallel()
	w := newWorld(t)
	fc := fakeClock(t)
	so := newSolo(t, w, nil, func(o *Options) { o.Clock = fc })
	if err := fc.WaitPending(context.Background(), 1); err != nil {
		t.Fatal(err)
	}
	fc.Advance(startWait)
	e := so.wantError(so.result(5*time.Second), protocol.ReasonControlTimeout)
	if e.Phase != protocol.PhaseCreated || e.Diagnostics != nil || e.Detail != "start_wait" {
		t.Fatalf("error %+v", e)
	}
	so.checkControlReturned()
}

// A frame of another major version: control_version_mismatch, nothing written.
func TestVersionMismatchWritesNothing(t *testing.T) {
	t.Parallel()
	w := newWorld(t)
	so := newSolo(t, w, nil, nil)
	if _, err := so.srvEnd.Write(rawFrame(2, byte(wiretype.PunchStart), []byte("{}"))); err != nil {
		t.Fatal(err)
	}
	so.wantFailure(so.result(5*time.Second), protocol.ReasonControlVersionMismatch)
	_ = so.srvEnd.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
	if n, _ := so.srvEnd.Read(make([]byte, 64)); n != 0 {
		t.Fatalf("client wrote %d bytes", n)
	}
	_ = so.srvEnd.SetReadDeadline(time.Time{})
	so.checkControlReturned()
}

// control.version != 1 inside a well-formed frame is a version mismatch too,
// and even a ping that came with it is not answered.
func TestControlVersionInStart(t *testing.T) {
	t.Parallel()
	w := newWorld(t)
	so := newSolo(t, w, nil, nil)
	ps := w.startFor(so.s, so.role, testTimeouts(), nil)
	ps.Control.Version = 2
	body, err := json.Marshal(ps)
	if err != nil {
		t.Fatal(err)
	}
	ping, _ := msgframe.Encode(protocol.Ping{Seq: 1})
	frames := append(rawFrame(1, byte(wiretype.PunchStart), body), rawFrame(1, byte(wiretype.Ping), ping.Payload)...)
	if _, err := so.srvEnd.Write(frames); err != nil {
		t.Fatal(err)
	}
	so.wantFailure(so.result(5*time.Second), protocol.ReasonControlVersionMismatch)
	_ = so.srvEnd.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
	if n, _ := so.srvEnd.Read(make([]byte, 64)); n != 0 {
		t.Fatalf("client wrote %d bytes", n)
	}
}

// An invalid punch_start that names its session is answered with
// punch_result{ok:false, protocol_violation}.
func TestInvalidStart(t *testing.T) {
	t.Parallel()
	w := newWorld(t)
	so := newSolo(t, w, nil, nil)
	ps := w.startFor(so.s, so.role, testTimeouts(), nil)
	ps.Token = protocol.Token{}
	body, err := json.Marshal(ps)
	if err != nil {
		t.Fatal(err)
	}
	so.open()
	if _, err := so.srvEnd.Write(rawFrame(1, byte(wiretype.PunchStart), body)); err != nil {
		t.Fatal(err)
	}
	pr := so.punchResult()
	if pr.OK || pr.Reason != protocol.ReasonProtocolViolation {
		t.Fatalf("punch_result %+v", pr)
	}
	e := so.wantError(so.result(5*time.Second), protocol.ReasonProtocolViolation)
	if e.Diagnostics == nil || e.Diagnostics.SessionID != so.s.sid {
		t.Fatalf("diagnostics %+v", e.Diagnostics)
	}
}

// No observers: no_probe_endpoint, reported with punch_result.
func TestNoObservers(t *testing.T) {
	t.Parallel()
	w := newWorld(t)
	so := newSolo(t, w, nil, nil)
	ps := w.startFor(so.s, so.role, testTimeouts(), nil)
	ps.Probe.Observers = nil
	so.open().send(ps)
	pr := so.punchResult()
	if pr.Reason != protocol.ReasonNoProbeEndpoint || pr.Phase != protocol.PhaseProbing {
		t.Fatalf("punch_result %+v", pr)
	}
	e := so.wantError(so.result(5*time.Second), protocol.ReasonNoProbeEndpoint)
	if e.Phase != protocol.PhaseProbing {
		t.Fatalf("phase %s", e.Phase)
	}
}

// Observers that never answer: the family fails probing within the probe
// timeout.
func TestProbeNoAnswer(t *testing.T) {
	t.Parallel()
	w := newWorld(t)
	so := newSolo(t, w, nil, nil)
	ps := w.startFor(so.s, so.role, testTimeouts(), nil)
	for i := range ps.Probe.Observers {
		ps.Probe.Observers[i].Addr = netipAP("192.0.2.200", 3478+i)
	}
	so.open().send(ps)
	pr := so.punchResult()
	if pr.OK || (pr.Reason != protocol.ReasonProbeTimeout && pr.Reason != protocol.ReasonUDPBlocked) {
		t.Fatalf("punch_result %+v", pr)
	}
	r := so.result(5 * time.Second)
	var e *Error
	if !errors.As(r.err, &e) || e.Reason != pr.Reason {
		t.Fatalf("error %v", r.err)
	}
}

// Every bind fails: local_port_bind_failed.
func TestBindFailure(t *testing.T) {
	t.Parallel()
	w := newWorld(t)
	so := newSolo(t, w, nil, nil)
	so.host.FailBinds("", -1)
	so.start(testTimeouts())
	pr := so.punchResult()
	if pr.Reason != protocol.ReasonLocalPortBindFailed {
		t.Fatalf("punch_result %+v", pr)
	}
	so.wantFailure(so.result(5*time.Second), protocol.ReasonLocalPortBindFailed)
}

// Summary wait: the server never sends the summary.
func TestSummaryWaitTimeout(t *testing.T) {
	t.Parallel()
	w := newWorld(t)
	so := newSolo(t, w, nil, nil)
	to := testTimeouts()
	to.SummaryWaitMs = 1000
	began := time.Now()
	so.start(to)
	so.report()
	r := so.result(10 * time.Second)
	e := so.wantError(r, protocol.ReasonControlTimeout)
	if e.Detail != "summary_wait" || e.Phase != protocol.PhaseReported {
		t.Fatalf("error %+v", e)
	}
	// summary_wait_ms plus the 2 s slack, counted from punch_start; the
	// rest is the cleanup.
	if took := r.at.Sub(began); took < 3*time.Second-50*time.Millisecond || took > 4500*time.Millisecond {
		t.Fatalf("the summary wait took %v", took)
	}
	so.checkControlReturned()
}

// An abort before the summary carries the server's code, by and retry.
func TestAbortBeforeSummary(t *testing.T) {
	t.Parallel()
	for _, c := range []struct {
		by     protocol.Role
		code   protocol.Reason
		reason protocol.Reason
	}{
		{protocol.RoleServer, protocol.ReasonServerBusy, protocol.ReasonServerBusy},
		{protocol.RoleResponder, "", protocol.ReasonAbortedByPeer},
		{protocol.RoleServer, "made_up", protocol.ReasonAbortedByServer},
	} {
		w := newWorld(t)
		so := newSolo(t, w, nil, nil)
		so.start(testTimeouts())
		so.report()
		so.link.send(protocol.Abort{SessionID: so.s.sid, By: c.by, Reason: c.code, Detail: "d", RetryAfterMs: 1500})
		e := so.wantError(so.result(5*time.Second), c.reason)
		if e.AbortedBy != c.by || e.RetryAfter != 1500*time.Millisecond || e.Detail != "d" {
			t.Fatalf("error %+v", e)
		}
	}
}

// A summary without a usable family: no_common_family, reported.
func TestNoCommonFamily(t *testing.T) {
	t.Parallel()
	w := newWorld(t)
	so := newSolo(t, w, nil, nil)
	to := testTimeouts()
	so.start(to)
	_, self := so.report()
	so.link.send(protocol.ProbeSummary{SessionID: so.s.sid, Self: self, Peer: protocol.PeerView{},
		Pair: protocol.PairFacts{}, Timeouts: to,
		Plan: protocol.PlanSpec{ID: "p", PairClass: "test", RoundsMax: 1, Budget: protocol.DefaultBudget(),
			Round1: protocol.RoundPlan{Round: 1, Variant: "v", Budget: protocol.BudgetLight, WindowMs: 800,
				Sides: []protocol.FamilySide{{Family: protocol.FamilyUDP4, Role: protocol.SideReplyOnly, Sockets: 1,
					Stages: []protocol.Stage{{Kind: protocol.StageReplyOnly}}}}}}})
	pr := so.punchResult()
	if pr.Reason != protocol.ReasonNoCommonFamily {
		t.Fatalf("punch_result %+v", pr)
	}
	so.wantFailure(so.result(5*time.Second), protocol.ReasonNoCommonFamily)
}

// Go wait: ready written, no go.
func TestGoWaitTimeout(t *testing.T) {
	t.Parallel()
	w := newWorld(t)
	so := newSolo(t, w, nil, nil)
	to := testTimeouts()
	to.GoWaitMs = 500
	so.start(to)
	_, self := so.report()
	so.summary(self, fakePeer("203.0.113.99:4000"), to)
	if _, ok := so.link.next(5*time.Second, protocol.MsgPunchReady); !ok {
		t.Fatal("no ready")
	}
	e := so.wantError(so.result(5*time.Second), protocol.ReasonControlTimeout)
	if e.Detail != "go_wait" || e.Phase != protocol.PhaseReady {
		t.Fatalf("error %+v", e)
	}
}

// The control link breaks before punching: control_interrupted at once.
func TestControlCutBeforePunching(t *testing.T) {
	t.Parallel()
	w := newWorld(t)
	so := newSolo(t, w, nil, nil)
	so.start(testTimeouts())
	so.report()
	so.srvEnd.Cut()
	e := so.wantError(so.result(5*time.Second), protocol.ReasonControlInterrupted)
	if e.Phase != protocol.PhaseReported {
		t.Fatalf("phase %s", e.Phase)
	}
}

// The caller closes the control connection: canceled, Err ErrClosed.
func TestCallerClosesControl(t *testing.T) {
	t.Parallel()
	w := newWorld(t)
	so := newSolo(t, w, nil, nil)
	so.start(testTimeouts())
	so.report()
	_ = so.cli.Close()
	e := so.wantError(so.result(5*time.Second), protocol.ReasonCanceled)
	if !errors.Is(e, ErrClosed) {
		t.Fatalf("err %v", e.Err)
	}
}

// The caller cancels: canceled at once, in every phase it waits in.
func TestCallerCancel(t *testing.T) {
	t.Parallel()
	w := newWorld(t)
	so := newSolo(t, w, nil, nil)
	so.start(testTimeouts())
	so.report()
	so.cancel()
	so.wantFailure(so.result(5*time.Second), protocol.ReasonCanceled)
	so.checkControlReturned()
}

// Frames out of order and malformed frames are protocol violations.
func TestProtocolViolations(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		do   func(so *solo)
	}{
		{"go before summary", func(so *solo) {
			so.link.send(protocol.PunchGo{SessionID: so.s.sid, Round: 1, WindowMs: 800})
		}},
		{"wrong session", func(so *solo) {
			so.link.send(protocol.PunchGo{SessionID: "other", Round: 1, WindowMs: 800})
		}},
		{"duplicate start", func(so *solo) {
			so.link.send(so.w.startFor(so.s, so.role, testTimeouts(), nil))
		}},
		{"bad json", func(so *solo) {
			_ = so.link.conn.Send(controlwire.Frame{Type: wiretype.ProbeSummary, Payload: []byte("[1,2]")})
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			w := newWorld(t)
			so := newSolo(t, w, nil, nil)
			so.start(testTimeouts())
			so.report()
			c.do(so)
			so.wantFailure(so.result(5*time.Second), protocol.ReasonProtocolViolation)
		})
	}
}

// A go whose plan is not where its round puts it is a protocol violation
// named by its detail: round 1's plan is the summary's, which
// its go may carry again only re-aimed by an anchor refresh — predict
// anchors and spans, nothing else; every later round carries its
// own.
func TestGoPlanPlacement(t *testing.T) {
	t.Parallel()
	for _, c := range []struct {
		name   string
		round  uint8
		plan   func(*protocol.RoundPlan) // nil: the go carries none
		detail string
	}{
		{"round 1 with more sockets", 1, func(p *protocol.RoundPlan) { p.Sides[0].Sockets++ }, "round1_plan"},
		{"round 1 with another direct target", 1, func(p *protocol.RoundPlan) {
			p.Sides[0].Stages[0].Targets = []netip.AddrPort{netipAP("203.0.113.98", 4000)}
		}, "round1_plan"},
		{"round 2 without plan", 2, nil, "plan"},
	} {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			w := newWorld(t)
			so := newSolo(t, w, nil, nil)
			to := testTimeouts()
			so.start(to)
			_, self := so.report()
			r1 := so.summary(self, fakePeer("203.0.113.99:4000"), to)
			if _, ok := so.link.next(5*time.Second, protocol.MsgPunchReady); !ok {
				t.Fatal("no ready")
			}
			g := protocol.PunchGo{SessionID: so.s.sid, Round: c.round, WindowMs: r1.WindowMs}
			if c.plan != nil {
				p := r1.Clone()
				c.plan(&p)
				g.Plan = &p
			}
			payload, err := json.Marshal(g) // the go a faulty server writes
			if err != nil {
				t.Fatal(err)
			}
			_ = so.link.conn.Send(controlwire.Frame{Type: wiretype.PunchGo, Payload: payload})
			pr := so.punchResult()
			if pr.OK || pr.Reason != protocol.ReasonProtocolViolation || pr.Detail != c.detail {
				t.Fatalf("punch_result %+v", pr)
			}
			e := so.wantError(so.result(5*time.Second), protocol.ReasonProtocolViolation)
			if e.Detail != c.detail || e.Phase != protocol.PhaseReady {
				t.Fatalf("detail %q phase %s", e.Detail, e.Phase)
			}
		})
	}
}

// A round-1 go may carry the summary's plan with its predict stages
// re-aimed by an anchor refresh: the client runs
// round 1 with the go's anchors and spans.
func TestGoAnchorUpdate(t *testing.T) {
	t.Parallel()
	w := newWorld(t)
	so := newSolo(t, w, nil, nil)
	to := testTimeouts()
	so.start(to)
	_, self := so.report()
	peer := fakePeer("203.0.113.99:4000")
	r1 := directPlan(1, so.role, roleViews(so.role, self, peer))
	side := &r1.Sides[0]
	side.Stages = append(side.Stages, protocol.Stage{Kind: protocol.StagePredict, AtMs: 20, IP: netip.MustParseAddr("203.0.113.99"),
		Anchor: 40000, Steps: []int16{1}, Span: 8})
	side.MaxPackets += 8
	side.MaxDistinctPorts += 8
	so.link.send(protocol.ProbeSummary{
		SessionID: so.s.sid, Self: self, Peer: peer,
		Pair:      protocol.PairFacts{SharedFamilies: []protocol.Family{protocol.FamilyUDP4}},
		Transport: protocol.TransportPick{Mode: "quic"}, Timeouts: to,
		Plan: protocol.PlanSpec{ID: "p", PairClass: "test", RoundsMax: 3, Budget: protocol.DefaultBudget(), Round1: r1},
	})
	if _, ok := so.link.next(5*time.Second, protocol.MsgPunchReady); !ok {
		t.Fatal("no ready")
	}
	up := r1.Reanchor(0, len(side.Stages)-1, 40003, 6)
	so.link.send(protocol.PunchGo{SessionID: so.s.sid, Round: 1, WindowMs: r1.WindowMs, Plan: &up})
	if m, ok := so.link.next(5*time.Second, protocol.MsgRoundResult, protocol.MsgPunchResult); !ok {
		t.Fatal("no round_result: round 1 did not run")
	} else if pr, isPR := m.(*protocol.PunchResult); isPR {
		t.Fatalf("punch_result %+v", pr)
	}
	so.link.send(protocol.Abort{SessionID: so.s.sid, By: protocol.RoleServer, Reason: protocol.ReasonCanceled})
	e := so.wantError(so.result(5*time.Second), protocol.ReasonCanceled)
	if len(e.Diagnostics.Rounds) != 1 {
		t.Fatalf("%d rounds in the diagnostics", len(e.Diagnostics.Rounds))
	}
	got := e.Diagnostics.Rounds[0].Sides[0]
	if st := got.Stages[len(got.Stages)-1]; st.Anchor != 40003 || st.Span != 6 || got.MaxPackets != up.Sides[0].MaxPackets {
		t.Fatalf("round 1 ran %+v (max_packets %d), want the go's anchor 40003 span 6", st, got.MaxPackets)
	}
}

// A go's window_ms is its plan's:
// round 1's go repeats the summary's round-1 plan, a later go its own plan.
// A go that names another window is a protocol violation with detail window
// in both cases, whichever way it differs and even when the value is valid
// on its own.
func TestGoWindow(t *testing.T) {
	t.Parallel()
	for _, c := range []struct {
		name  string
		round uint8
		delta int
	}{{"round 1 longer", 1, 1}, {"round 1 shorter", 1, -100}, {"round 2 longer", 2, 1}, {"round 2 shorter", 2, -100}} {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			w := newWorld(t)
			so := newSolo(t, w, nil, nil)
			to := testTimeouts()
			so.start(to)
			_, self := so.report()
			r1 := so.summary(self, fakePeer("203.0.113.99:4000"), to)
			if _, ok := so.link.next(5*time.Second, protocol.MsgPunchReady); !ok {
				t.Fatal("no ready")
			}
			g := protocol.PunchGo{SessionID: so.s.sid, Round: c.round, WindowMs: uint16(int(r1.WindowMs) + c.delta)}
			if c.round == 1 {
				if _, err := msgframe.Encode(g); err != nil {
					t.Fatalf("the go is valid on its own: %v", err)
				}
				so.link.send(g)
			} else {
				p := r1
				p.Round = c.round
				g.Plan = &p
				payload, err := json.Marshal(g) // the go a faulty server writes
				if err != nil {
					t.Fatal(err)
				}
				_ = so.link.conn.Send(controlwire.Frame{Type: wiretype.PunchGo, Payload: payload})
			}
			pr := so.punchResult()
			if pr.OK || pr.Reason != protocol.ReasonProtocolViolation || pr.Detail != "window" {
				t.Fatalf("punch_result %+v", pr)
			}
			e := so.wantError(so.result(5*time.Second), protocol.ReasonProtocolViolation)
			if e.Detail != "window" || e.Phase != protocol.PhaseReady || len(e.Diagnostics.Rounds) != 0 {
				t.Fatalf("detail %q phase %s rounds %d", e.Detail, e.Phase, len(e.Diagnostics.Rounds))
			}
		})
	}
}

// A bad magic number before punch_start is a protocol violation too.
func TestBadMagic(t *testing.T) {
	t.Parallel()
	w := newWorld(t)
	so := newSolo(t, w, nil, nil)
	if _, err := so.srvEnd.Write([]byte("GET / HTTP/1.1\r\n")); err != nil {
		t.Fatal(err)
	}
	e := so.wantError(so.result(5*time.Second), protocol.ReasonProtocolViolation)
	if e.Diagnostics != nil {
		t.Fatal("no diagnostics before punch_start")
	}
}

// Punching towards a silent peer: rounds end with window_end, the server
// stops answering, the gap deadline attributes the failure from this side's
// evidence.
func TestPunchingSilentPeerAttribution(t *testing.T) {
	t.Parallel()
	w := newWorld(t)
	so := newSolo(t, w, nil, nil)
	to := testTimeouts()
	to.GoWaitMs = 500
	so.start(to)
	_, self := so.report()
	r1 := so.summary(self, fakePeer("203.0.113.99:4000"), to)
	if _, ok := so.link.next(5*time.Second, protocol.MsgPunchReady); !ok {
		t.Fatal("no ready")
	}
	so.link.send(protocol.PunchGo{SessionID: so.s.sid, Round: 1, DelayMs: 10, WindowMs: r1.WindowMs, RTTMs: 4})
	m, ok := so.link.next(5*time.Second, protocol.MsgRoundResult)
	if !ok {
		t.Fatal("no round_result")
	}
	rr := m.(*protocol.RoundResult)
	if rr.Status != protocol.RoundWindowEnd || len(rr.Families) != 1 || rr.Families[0].Sent == 0 || rr.Families[0].Recv != 0 {
		t.Fatalf("round_result %+v", rr)
	}
	pr := so.punchResult()
	if pr.OK || pr.Reason != protocol.ReasonCandidateTimeout {
		t.Fatalf("punch_result %+v", pr)
	}
	e := so.wantError(so.result(5*time.Second), protocol.ReasonCandidateTimeout)
	d := e.Diagnostics
	if e.Round != 1 || d == nil || d.Counters.TxPackets == 0 || d.Counters.TxByStage["direct"] == 0 || len(d.Rounds) != 1 || d.RTT != 4*time.Millisecond {
		t.Fatalf("error %+v diag %+v", e, d)
	}
}

// The control link breaks while punching: the round runs out, then 500 ms of
// grace, then control_interrupted; no new round starts.
func TestControlCutWhilePunching(t *testing.T) {
	t.Parallel()
	w := newWorld(t)
	so := newSolo(t, w, nil, nil)
	to := testTimeouts()
	so.start(to)
	_, self := so.report()
	r1 := so.summary(self, fakePeer("203.0.113.99:4000"), to)
	if _, ok := so.link.next(5*time.Second, protocol.MsgPunchReady); !ok {
		t.Fatal("no ready")
	}
	goSent := time.Now()
	so.link.send(protocol.PunchGo{SessionID: so.s.sid, Round: 1, WindowMs: r1.WindowMs})
	// Cut once round 1 runs, which go_received reports, however long the
	// client takes to read the go.
	for until := time.Now().Add(testkit.WaitBound(t)); ; {
		m, ok := so.link.next(time.Until(until), protocol.MsgProgress)
		if !ok {
			t.Fatal("no go_received")
		}
		if m.(*protocol.Progress).Stage == stageGoReceived {
			break
		}
	}
	cut := time.Now()
	so.srvEnd.Cut()
	r := so.result(5 * time.Second)
	so.wantFailure(r, protocol.ReasonControlInterrupted)
	window := time.Duration(r1.WindowMs) * time.Millisecond
	// The round fires once the go is read and runs its whole window, then
	// the grace; it started before the cut.
	if since := r.at.Sub(goSent); since < window {
		t.Fatalf("returned %v after the go, window %v", since, window)
	}
	if took := r.at.Sub(cut); took > window+confirmGrace+time.Second {
		t.Fatalf("returned %v after the cut, window %v", took, window)
	}
}

// An abort while punching fails at once with its code.
func TestAbortWhilePunching(t *testing.T) {
	t.Parallel()
	w := newWorld(t)
	so := newSolo(t, w, nil, nil)
	to := testTimeouts()
	so.start(to)
	_, self := so.report()
	r1 := so.summary(self, fakePeer("203.0.113.99:4000"), to)
	if _, ok := so.link.next(5*time.Second, protocol.MsgPunchReady); !ok {
		t.Fatal("no ready")
	}
	so.link.send(protocol.PunchGo{SessionID: so.s.sid, Round: 1, WindowMs: r1.WindowMs})
	so.link.send(protocol.Abort{SessionID: so.s.sid, By: protocol.RoleServer, Reason: protocol.ReasonHardSymmetricRandom})
	e := so.wantError(so.result(5*time.Second), protocol.ReasonHardSymmetricRandom)
	if e.AbortedBy != protocol.RoleServer {
		t.Fatalf("by %s", e.AbortedBy)
	}
}

// A side whose writes have all failed for blockedAfter reports
// round_result{fatal, udp_blocked}; a punch_abort the server sends after it
// — candidate_timeout, the session's attribution while only this side is
// blocked — ends the session with the local udp_blocked, keeping the abort's
// sender and retry advice.
func TestAbortAfterFatalKeepsUDPBlocked(t *testing.T) {
	t.Parallel()
	w := newWorld(t)
	so := newSolo(t, w, nil, nil)
	to := testTimeouts()
	so.start(to)
	_, self := so.report()
	r1 := so.summary(self, fakePeer(silentPeer), to)
	if _, ok := so.link.next(5*time.Second, protocol.MsgPunchReady); !ok {
		t.Fatal("no ready")
	}
	so.host.FailWrites("", -1, syscall.EPERM)
	var fatal *protocol.RoundResult
	for k := uint8(1); fatal == nil; k++ {
		if k > 3 {
			t.Fatal("no round_result{fatal} after three rounds of failing writes")
		}
		g := protocol.PunchGo{SessionID: so.s.sid, Round: k, WindowMs: r1.WindowMs}
		if k > 1 {
			p := r1
			p.Round = k
			g.Plan = &p
		}
		so.link.send(g)
		m, ok := so.link.next(5*time.Second, protocol.MsgRoundResult)
		if !ok {
			t.Fatalf("no round_result %d", k)
		}
		if rr := m.(*protocol.RoundResult); rr.Status == protocol.RoundFatal {
			fatal = rr
		}
	}
	if fatal.Reason != protocol.ReasonUDPBlocked {
		t.Fatalf("round_result %+v", fatal)
	}
	so.link.send(protocol.Abort{SessionID: so.s.sid, By: protocol.RoleServer, Reason: protocol.ReasonCandidateTimeout, RetryAfterMs: 700})
	if pr := so.punchResult(); pr.Reason != protocol.ReasonUDPBlocked {
		t.Fatalf("punch_result %+v", pr)
	}
	e := so.wantError(so.result(5*time.Second), protocol.ReasonUDPBlocked)
	if e.Detail != "send_failed" || e.AbortedBy != protocol.RoleServer || e.RetryAfter != 700*time.Millisecond {
		t.Fatalf("error %+v", e)
	}
}

// Options and control checks happen before anything is read or written.
func TestOptionChecks(t *testing.T) {
	t.Parallel()
	w := newWorld(t)
	h := w.host(nil)
	c, s := w.pipe(h, 0)
	defer func() { _ = c.Close() }()
	defer func() { _ = s.Close() }()
	var nilPipe *nattest.PipeConn
	var nilHost *nattest.Host
	cases := []struct {
		name    string
		control net.Conn
		o       Options
		detail  string
	}{
		{"nil control", nil, clientOpts(h), "nil_control"},
		{"typed nil control", nilPipe, clientOpts(h), "nil_control"},
		{"insecure", c, Options{Network: h}, "insecure_control"},
		{"bad security", c, Options{Network: h, ControlSecurity: 9}, "control_security"},
		{"long mode", c, func() Options { o := clientOpts(h); o.TransportMode = "a-very-long-transport-name"; return o }(), "transport_mode"},
		{"big data", c, func() Options { o := clientOpts(h); o.TransportData = make([]byte, 9000); return o }(), "transport_data"},
		{"typed nil network", c, Options{ControlSecurity: protocol.ControlSecurityDeclared, Network: nilHost}, "nil_network"},
		{"too many hops", c, func() Options {
			o := clientOpts(h)
			o.Policy = &protocol.Policy{LowTTLHops: []int{2, 3, 4, 5, 6, 7, 8, 9, 10}}
			return o
		}(), "policy.low_ttl_hops"},
		{"bad birthday", c, func() Options {
			o := clientOpts(h)
			o.Policy = &protocol.Policy{Budget: protocol.Budget{Birthday: "huge"}}
			return o
		}(), "policy.budget.birthday"},
	}
	for _, tc := range cases {
		_, err := Punch(context.Background(), tc.control, tc.o)
		var e *Error
		if !errors.As(err, &e) || e.Reason != protocol.ReasonInvalidArgument || e.Detail != tc.detail || e.Phase != protocol.PhaseCreated {
			t.Errorf("%s: %v", tc.name, err)
		}
	}
	// nothing was read or written: the pipe is still usable as is
	go func() { _, _ = s.Write([]byte{7}) }()
	b := make([]byte, 1)
	if _, err := c.Read(b); err != nil || b[0] != 7 {
		t.Fatalf("control touched: %v", err)
	}
}

// A connection without deadline support is refused.
func TestDeadlineUnsupported(t *testing.T) {
	t.Parallel()
	a, b := net.Pipe()
	defer func() { _ = a.Close() }()
	defer func() { _ = b.Close() }()
	fc := faultconn.Wrap(a)
	fc.NoDeadlines()
	_, err := Punch(context.Background(), fc, Options{ControlSecurity: protocol.ControlSecurityDeclared})
	var e *Error
	if !errors.As(err, &e) || e.Reason != protocol.ReasonInvalidArgument || e.Detail != "deadline_unsupported" {
		t.Fatalf("got %v", err)
	}
}

// A control write failure while probing ends the session at once with
// control_interrupted, the failed write as its cause. The observers never
// answer and the probe timeout is its 10 s maximum, so the session is still
// probing when the first frame it writes (the pong or a progress frame)
// fails. With answering observers, probing could finish, queue probe_report
// and reach reported before a slow writer got to its first write.
func TestControlWriteFailure(t *testing.T) {
	t.Parallel()
	w := newWorld(t)
	h := w.host(nil)
	c, s := w.pipe(h, time.Millisecond)
	defer func() { _ = s.Close() }()
	fc := faultconn.Wrap(c)
	fc.FailWrites(syscall.EPIPE)
	res := runClient(context.Background(), fc, clientOpts(h))
	sess := w.newSession()
	l := newSrvLink(t, s)
	defer l.close()
	to := testTimeouts()
	to.ProbeTimeoutMs = 10000
	ps := w.startFor(sess, protocol.RoleInitiator, to, nil)
	for i := range ps.Probe.Observers {
		ps.Probe.Observers[i].Addr = netipAP("192.0.2.200", 3478+i)
	}
	l.send(ps)
	l.send(protocol.Ping{Seq: 1})
	r := <-res
	var e *Error
	if !errors.As(r.err, &e) || e.Reason != protocol.ReasonControlInterrupted || e.Phase != protocol.PhaseProbing {
		t.Fatalf("got %v", r.err)
	}
	if !errors.Is(e, syscall.EPIPE) {
		t.Fatalf("cause %v, want the failed write's EPIPE", e.Err)
	}
}

// Back-pressure: the server stops reading, the report cannot be written
// within its 2 s deadline, the link is dead: control_interrupted.
func TestControlBackpressure(t *testing.T) {
	t.Parallel()
	w := newWorld(t)
	h := w.host(nil)
	c, s := w.n.Pipe(nattest.PipeConfig{A: h, B: w.server, BufferBytes: 64})
	defer func() { _ = s.Close() }()
	sess := w.newSession()
	res := runClient(context.Background(), c, clientOpts(h))
	fr, _ := msgframe.Encode(w.startFor(sess, protocol.RoleInitiator, testTimeouts(), nil))
	go func() { _, _ = s.Write(rawFrame(1, byte(fr.Type), fr.Payload)) }()
	began := time.Now()
	r := <-res
	var e *Error
	if !errors.As(r.err, &e) || e.Reason != protocol.ReasonControlInterrupted {
		t.Fatalf("got %v", r.err)
	}
	if d := time.Since(began); d > 5*time.Second {
		t.Fatalf("took %v", d)
	}
}
