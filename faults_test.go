//go:build holepunch_faultinject

package holepunch

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/djylb/holepunch/internal/faultinject"
	"github.com/djylb/holepunch/nattest"
	"github.com/djylb/holepunch/protocol"
)

// fiProbeRecv is internal/probe's injection point for every packet it is
// delivered.
const fiProbeRecv = "probe.recv"

// soloToGo runs a solo session up to its first go towards a silent peer.
func soloToGo(t *testing.T) *solo {
	t.Helper()
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
	so.link.send(protocol.PunchGo{SessionID: so.s.sid, Round: 1, WindowMs: r1.WindowMs})
	return so
}

func wantInternal(t *testing.T, so *solo, prefix string) {
	t.Helper()
	e := so.wantError(so.result(10*time.Second), protocol.ReasonInternal)
	if !strings.HasPrefix(e.Detail, prefix) {
		t.Fatalf("detail %q, want prefix %q", e.Detail, prefix)
	}
	if !strings.HasPrefix(prefix, "panic:") {
		return
	}
	// Every recovered panic reaches Error.Err, the prober's too, which it
	// hands over in its failed family result.
	var pe *PanicError
	if !errors.As(e, &pe) {
		t.Fatalf("no *PanicError in %v", e.Err)
	}
	if strings.HasPrefix(prefix, "panic:probe/") && e.Detail != "panic:"+pe.Where() {
		t.Fatalf("detail %q, panic in %q", e.Detail, pe.Where())
	}
}

// A panic at an injection point or in a named goroutine becomes internal
// with the goroutine's name; nothing leaks.
func TestFaultPanics(t *testing.T) {
	cases := []struct {
		point, prefix string
		setup         func(t *testing.T) *solo
	}{
		{fiRoundStage, "panic:round:udp4", soloToGo},
		{fiWaitSummary, "panic:attach", func(t *testing.T) *solo {
			so := newSolo(t, newWorld(t), nil, nil)
			so.start(testTimeouts())
			return so
		}},
		{fiAssistHandle, "panic:attach", func(t *testing.T) *solo {
			so := soloToGo(t)
			so.link.send(protocol.Assist{SessionID: so.s.sid, From: protocol.RoleServer, Kind: protocol.AssistPeerTargets, Round: 1,
				Family: protocol.FamilyUDP4, Source: protocol.TargetsInject,
				Window: &protocol.PortWindow{IP: netipAP("203.0.113.99", 0).Addr(), Lo: 4000, Hi: 4002}})
			return so
		}},
		{fiReadloopPacket, "panic:udp-read", func(t *testing.T) *solo {
			so := newSolo(t, newWorld(t), nil, nil)
			so.start(testTimeouts())
			return so
		}},
		// the prober recovers its own panics and fails its family; with
		// its only family failed the session carries the prober's detail
		{fiProbeSend, "panic:probe/udp4", func(t *testing.T) *solo {
			so := newSolo(t, newWorld(t), nil, nil)
			so.start(testTimeouts())
			return so
		}},
		{fiProbeRecv, "panic:probe/udp4", func(t *testing.T) *solo {
			so := newSolo(t, newWorld(t), nil, nil)
			so.start(testTimeouts())
			return so
		}},
	}
	for _, c := range cases {
		t.Run(c.point, func(t *testing.T) {
			disarm := faultinject.Arm(c.point, faultinject.Panic(), 0)
			defer disarm()
			so := c.setup(t)
			wantInternal(t, so, c.prefix)
		})
	}
}

// Injected errors at the socket and send points.
func TestFaultErrors(t *testing.T) {
	cases := []struct {
		point  string
		reason protocol.Reason
	}{
		{fiProbeBind, protocol.ReasonLocalPortBindFailed},
		{fiProbeSend, protocol.ReasonUDPBlocked},
		{fiReadloopPacket, protocol.ReasonProbeTimeout},
	}
	for _, c := range cases {
		t.Run(c.point, func(t *testing.T) {
			disarm := faultinject.Arm(c.point, faultinject.Error(nil), 0)
			defer disarm()
			so := newSolo(t, newWorld(t), nil, nil)
			so.start(testTimeouts())
			so.wantFailure(so.result(10*time.Second), c.reason)
		})
	}
	t.Run(fiAttachReadStart, func(t *testing.T) {
		disarm := faultinject.Arm(fiAttachReadStart, faultinject.Error(nil), 0)
		defer disarm()
		so := newSolo(t, newWorld(t), nil, nil)
		e := so.wantError(so.result(5*time.Second), protocol.ReasonInternal)
		if e.Diagnostics != nil {
			t.Fatal("diagnostics before punch_start")
		}
	})
	t.Run(fiWaitGo, func(t *testing.T) {
		disarm := faultinject.Arm(fiWaitGo, faultinject.Error(nil), 0)
		defer disarm()
		so := newSolo(t, newWorld(t), nil, nil)
		so.start(testTimeouts())
		_, self := so.report()
		so.summary(self, fakePeer("203.0.113.99:4000"), testTimeouts())
		so.wantFailure(so.result(5*time.Second), protocol.ReasonInternal)
	})
}

// Faults in the handover path of a real pair.
func TestFaultHandover(t *testing.T) {
	t.Run("finalize.disown", func(t *testing.T) {
		disarm := faultinject.Arm(fiFinalizeDisown, faultinject.Error(nil), 0)
		defer disarm()
		w := newWorld(t)
		pr := runPair(t, w, [2]*nattest.NATConfig{prc(), prc()}, &pairScript{w: w, timeouts: testTimeouts()}, nil)
		defer pr.closeAll()
		for i, r := range pr.res {
			var e *Error
			if !errors.As(r.err, &e) || e.Reason != protocol.ReasonInternal || e.Detail != "disown" {
				t.Fatalf("client %d: %v", i, r.err)
			}
			if n := pr.hosts[i].OpenSockets(); n != 0 {
				t.Fatalf("client %d kept %d sockets", i, n)
			}
		}
	})
	t.Run("result.write", func(t *testing.T) {
		disarm := faultinject.Arm(fiResultWrite, faultinject.Error(nil), 0)
		defer disarm()
		w := newWorld(t)
		ps := &pairScript{w: w, timeouts: testTimeouts(), stopAfterConfirm: true}
		pr := runPair(t, w, [2]*nattest.NATConfig{prc(), prc()}, ps, nil)
		defer pr.closeAll()
		wantSuccess(t, pr)
		if ps.results[0] != nil || ps.results[1] != nil {
			t.Fatal("punch_result written despite the fault")
		}
	})
	// A panic in finish after the winner was disowned (step 5) fails the
	// session, and the winner and its port mapping, which would now be
	// nobody's, are closed rather than leaked.
	t.Run("result.write panic", func(t *testing.T) {
		disarm := faultinject.Arm(fiResultWrite, faultinject.Panic(), 0)
		defer disarm()
		w := newWorld(t)
		ps := &pairScript{w: w, timeouts: testTimeouts(), resultWait: 2 * time.Second}
		var maps [2]*fakeMapper
		pr := runPair(t, w, [2]*nattest.NATConfig{prc(), prc()}, ps, func(i int, o *Options) {
			maps[i] = &fakeMapper{ext: netipAP("198.51.100.200", 30000+i)}
			o.PortMapper = maps[i]
		})
		defer pr.closeAll()
		for i, r := range pr.res {
			var e *Error
			if !errors.As(r.err, &e) || e.Reason != protocol.ReasonInternal || e.Detail != "panic:finish.result" || r.sess != nil {
				t.Fatalf("client %d: %v", i, r.err)
			}
			if n := pr.hosts[i].OpenSockets(); n != 0 {
				t.Fatalf("client %d kept %d sockets", i, n)
			}
			if m := maps[i]; m.mapped.Load() != m.released.Load() {
				t.Fatalf("client %d: %d mappings, %d released", i, m.mapped.Load(), m.released.Load())
			}
		}
	})
	t.Run("handover.ack", func(t *testing.T) {
		disarm := faultinject.Arm(fiHandoverAck, faultinject.Error(nil), 0)
		defer disarm()
		w := newWorld(t)
		pr := runPair(t, w, [2]*nattest.NATConfig{prc(), prc()}, &pairScript{w: w, timeouts: testTimeouts()}, nil)
		defer pr.closeAll()
		wantSuccess(t, pr)
		if by := pr.res[0].sess.Diagnostics().Path.ConfirmedBy; by != protocol.ConfirmedByQuiet {
			t.Fatalf("initiator confirmed by %s, want quiet", by)
		}
	})
	t.Run("nomination.retry", func(t *testing.T) {
		disarm := faultinject.Arm(fiNominationRetry, faultinject.Error(nil), 0)
		defer disarm()
		w := newWorld(t)
		to := testTimeouts()
		to.MaxRounds = 1
		pr := runPair(t, w, [2]*nattest.NATConfig{prc(), prc()}, &pairScript{w: w, timeouts: to}, nil)
		defer pr.closeAll()
		var e *Error
		if !errors.As(pr.res[0].err, &e) || e.Reason != protocol.ReasonCandidateTimeout {
			t.Fatalf("initiator: %v", pr.res[0].err)
		}
	})
	t.Run("progress.deliver", func(t *testing.T) {
		disarm := faultinject.Arm(fiProgressDeliver, faultinject.Panic(), 0)
		defer disarm()
		w := newWorld(t)
		pr := runPair(t, w, [2]*nattest.NATConfig{prc(), prc()}, &pairScript{w: w, timeouts: testTimeouts()}, func(i int, o *Options) {
			o.OnProgress = func(protocol.Progress) {}
		})
		defer pr.closeAll()
		wantSuccess(t, pr)
		if pr.res[0].sess.Diagnostics().Counters.CallbackPanics == 0 {
			t.Fatal("delivery panics not counted")
		}
	})
	t.Run("portmap.map", func(t *testing.T) {
		disarm := faultinject.Arm(fiPortmapMap, faultinject.Error(nil), 0)
		defer disarm()
		w := newWorld(t)
		pr := runPair(t, w, [2]*nattest.NATConfig{prc(), prc()}, &pairScript{w: w, timeouts: testTimeouts()}, func(i int, o *Options) {
			o.PortMapper = &fakeMapper{ext: netipAP("198.51.100.200", 30000)}
		})
		defer pr.closeAll()
		wantSuccess(t, pr)
		if pr.res[0].sess.Result().Path.PortMapping != nil {
			t.Fatal("failed mapping reported")
		}
	})
}
