package coord

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/djylb/holepunch/coord/internal/faultconn"
	"github.com/djylb/holepunch/coord/internal/simclient"
	"github.com/djylb/holepunch/protocol"
)

// TestHappyPath runs a session from NewSession to a confirmed success.
func TestHappyPath(t *testing.T) {
	r := newRig(t)
	p := r.pair(SessionOptions{Labels: map[string]string{"k": "v"}})
	gos := p.punching()
	for i := range 2 {
		if gos[i].Round != 1 || gos[i].Plan != nil {
			t.Fatalf("go %d: %+v", i, gos[i])
		}
	}
	p.confirm(0, 1)
	p.confirm(1, 1)
	p.succeed(0, 1)
	p.succeed(1, 1)
	res := r.wait(p.s)
	if res.Outcome != OutcomeSucceeded || res.Code != "" || res.Confirmed != [2]bool{true, true} {
		t.Fatalf("result %+v", res)
	}
	if res.Winner == nil || res.Winner.Round != 1 || res.Labels["k"] != "v" || res.Winner.Path[0] == nil {
		t.Fatalf("winner %+v labels %v", res.Winner, res.Labels)
	}
	for i := range 2 {
		expectEOF(t, p.cl[i])
	}
	if got := <-r.results; got.SessionID != p.s.ID() {
		t.Fatalf("OnResult %+v", got)
	}
	if r.c.Len() != 0 || r.c.Stats().ActiveByKey != 0 {
		t.Fatalf("Len %d stats %+v", r.c.Len(), r.c.Stats())
	}
	if len(res.Rounds) != 1 || res.Rounds[0].Class != RoundConfirmed || res.Rounds[0].Granted[0] == 0 {
		t.Fatalf("rounds %+v", res.Rounds)
	}
	if res.Clients[0] == nil || !res.Clients[0].OK || res.Timings.FirstGo.IsZero() || res.Timings.Summary.IsZero() {
		t.Fatalf("clients %+v timings %+v", res.Clients, res.Timings)
	}
	if !errors.Is(context.Cause(p.s.Context()), ErrSessionDone) {
		t.Fatalf("cause %v", context.Cause(p.s.Context()))
	}
	st := r.c.Stats()
	if st.SessionsTotal != 1 || st.ByOutcome[0] != 1 || st.ConfirmAtRound[1] != 1 {
		t.Fatalf("stats %+v", st)
	}
}

// TestAttachOrderIndependent: either side may attach first, and the first
// side's early report is kept and used.
func TestAttachOrderIndependent(t *testing.T) {
	for _, first := range []int{0, 1} {
		r := newRig(t)
		s := r.session(SessionOptions{})
		p := &pair{r: r, s: s}
		p.cl[first] = r.attach(s, roleOf(first))
		p.starts[first] = expect[protocol.PunchStart](t, p.cl[first])
		if snap := s.Snapshot(); snap.State != StateBinding {
			t.Fatalf("state %s", snap.State)
		}
		if p.starts[first].Timeouts.SummaryWaitMs < 15000 {
			t.Fatalf("summary_wait_ms %d", p.starts[first].Timeouts.SummaryWaitMs)
		}
		p.report(first)
		eventually(t, "early report", func() bool { return s.Snapshot().Reported[first] })
		second := 1 - first
		p.cl[second] = r.attach(s, roleOf(second))
		p.starts[second] = expect[protocol.PunchStart](t, p.cl[second])
		if got := p.starts[second].Timeouts.SummaryWaitMs; got != 5000 {
			t.Fatalf("second summary_wait_ms %d", got)
		}
		p.report(second)
		for i := range 2 {
			sum := expect[protocol.ProbeSummary](t, p.cl[i])
			send(t, p.cl[i], simclient.Ready(sum, roleOf(i), 1))
		}
		for i := range 2 {
			expect[protocol.PunchGo](t, p.cl[i])
		}
		p.state(StatePunching)
		p.s.Abort(protocol.ReasonCanceled, "test")
		if res := r.wait(s); res.Code != protocol.ReasonCanceled || res.Outcome != OutcomeAborted {
			t.Fatalf("result %+v", res)
		}
	}
}

// TestAttachErrors: every refusal leaves the connection with the caller,
// unread and unwritten.
func TestAttachErrors(t *testing.T) {
	r := newRig(t)
	s := r.session(SessionOptions{})
	srv, cli := net.Pipe()
	defer func() { _ = srv.Close() }()
	defer func() { _ = cli.Close() }()
	insecure := AttachOptions{Security: protocol.ControlSecurityInsecureForTesting}
	var nilConn *net.TCPConn
	errInvalidArgument := errors.New("an invalid_argument refusal") // matched by invalidArgument
	cases := []struct {
		name string
		err  error
		do   func() error
	}{
		{"role", ErrInvalidRole, func() error { return s.Attach(protocol.RoleServer, srv, insecure) }},
		{"nil", ErrInvalidConn, func() error { return s.Attach(protocol.RoleInitiator, nil, insecure) }},
		{"typed nil", ErrInvalidConn, func() error { return s.Attach(protocol.RoleInitiator, nilConn, insecure) }},
		{"insecure", errInvalidArgument, func() error { return s.Attach(protocol.RoleInitiator, srv, AttachOptions{}) }},
		{"tls not done", errInvalidArgument, func() error {
			return s.Attach(protocol.RoleInitiator, tlsConn{Conn: srv}, AttachOptions{})
		}},
		{"security value", errInvalidArgument, func() error {
			return s.Attach(protocol.RoleInitiator, srv, AttachOptions{Security: 9})
		}},
		{"no deadlines", ErrInvalidConn, func() error {
			fc := faultconn.Wrap(srv)
			fc.NoDeadlines()
			return s.Attach(protocol.RoleInitiator, fc, insecure)
		}},
	}
	for _, c := range cases {
		err := c.do()
		ok := errors.Is(err, c.err)
		if errors.Is(c.err, errInvalidArgument) {
			ok = invalidArgument(err)
		}
		if !ok {
			t.Errorf("%s: %v, want %v", c.name, err, c.err)
		}
	}
	if snap := s.Snapshot(); snap.State != StateCreated || snap.Attached != [2]bool{} {
		t.Fatalf("state changed: %+v", snap)
	}
	// The caller still owns the connection: it works both ways.
	go func() { _, _ = cli.Write([]byte("x")) }()
	buf := make([]byte, 1)
	if _, err := srv.Read(buf); err != nil {
		t.Fatalf("conn unusable: %v", err)
	}

	// A completed TLS handshake and a declared stream are accepted.
	a, b := net.Pipe()
	defer func() { _ = b.Close() }()
	if err := s.Attach(protocol.RoleInitiator, tlsConn{Conn: a, done: true}, AttachOptions{}); err != nil {
		t.Fatal(err)
	}
	c, d := net.Pipe()
	defer func() { _ = d.Close() }()
	if err := s.Attach(protocol.RoleInitiator, c, AttachOptions{Security: protocol.ControlSecurityDeclared}); !errors.Is(err, ErrAlreadyAttached) {
		t.Fatalf("second initiator: %v", err)
	}
	if err := s.Attach(protocol.RoleResponder, c, AttachOptions{Security: protocol.ControlSecurityDeclared}); err != nil {
		t.Fatal(err)
	}
	s.Abort("bogus", "")
	if res := r.wait(s); res.Code != protocol.ReasonCanceled {
		t.Fatalf("unknown code: %+v", res)
	}
}

// tlsConn reports a TLS connection state.
type tlsConn struct {
	net.Conn
	done bool
}

func (c tlsConn) ConnectionState() tls.ConnectionState {
	return tls.ConnectionState{HandshakeComplete: c.done}
}

// TestAttachAfterClose: a session that ended refuses Attach and does not
// take the connection.
func TestAttachAfterClose(t *testing.T) {
	r := newRig(t)
	s := r.session(SessionOptions{})
	r.clk.Advance(defBindTimeout)
	res := r.wait(s)
	if res.Code != protocol.ReasonPeerOffline || res.Detail != detailJoinTimeout || res.FailedRole != "" {
		t.Fatalf("result %+v", res)
	}
	srv, cli := net.Pipe()
	defer func() { _ = cli.Close() }()
	defer func() { _ = srv.Close() }()
	if err := s.Attach(protocol.RoleInitiator, srv, AttachOptions{Security: protocol.ControlSecurityDeclared}); !errors.Is(err, ErrSessionDone) {
		t.Fatalf("attach: %v", err)
	}
	go func() { _, _ = srv.Write([]byte("y")) }()
	if _, err := cli.Read(make([]byte, 1)); err != nil {
		t.Fatalf("conn closed: %v", err)
	}
	if err := r.c.Close(); err != nil {
		t.Fatal(err)
	}
	if err := s.Attach(protocol.RoleInitiator, srv, AttachOptions{Security: protocol.ControlSecurityDeclared}); !errors.Is(err, ErrClosed) {
		t.Fatalf("attach after close: %v", err)
	}
	if _, err := r.c.NewSession(SessionOptions{}); !errors.Is(err, ErrClosed) {
		t.Fatalf("NewSession after close: %v", err)
	}
}

// TestSucceededReleasesImmediately: two confirmations and two punch_result
// frames end the session at once; two confirmations alone end it after
// ResultGrace.
func TestSucceededReleasesImmediately(t *testing.T) {
	r := newRig(t)
	p := r.pair(SessionOptions{})
	p.punching()
	p.confirm(0, 1)
	p.confirm(1, 1)
	p.state(StateConfirming)
	eventually(t, "both confirmed", func() bool { return p.s.Snapshot().Confirmed == [2]bool{true, true} })
	r.clk.Advance(defResultGrace - time.Millisecond)
	select {
	case <-p.s.Done():
		t.Fatal("released before ResultGrace")
	default:
	}
	r.clk.Advance(time.Millisecond)
	res := r.wait(p.s)
	if res.Outcome != OutcomeSucceeded || res.Confirmed != [2]bool{true, true} || contains(res.Warn, protocol.WarnPeerResultMissing) {
		t.Fatalf("result %+v", res)
	}
}

// TestConfirmLinger: one confirmation ends the session as a half-confirmed
// success after ConfirmLinger, at once when the other side's link drops, and
// a failure report of the other side does not change that.
func TestConfirmLinger(t *testing.T) {
	t.Run("linger", func(t *testing.T) {
		r := newRig(t)
		p := r.pair(SessionOptions{})
		p.punching()
		p.confirm(0, 1)
		p.state(StateConfirming)
		r.clk.Advance(3*time.Second - time.Millisecond)
		select {
		case <-p.s.Done():
			t.Fatal("ended before ConfirmLinger")
		default:
		}
		r.clk.Advance(time.Millisecond)
		res := r.wait(p.s)
		if res.Outcome != OutcomeSucceeded || res.Confirmed != [2]bool{true, false} || !contains(res.Warn, protocol.WarnPeerResultMissing) {
			t.Fatalf("result %+v", res)
		}
		if r.c.Stats().HalfConfirmed != 1 {
			t.Fatalf("stats %+v", r.c.Stats())
		}
	})
	t.Run("unconfirmed drops", func(t *testing.T) {
		r := newRig(t)
		p := r.pair(SessionOptions{})
		p.punching()
		p.confirm(0, 1)
		p.state(StateConfirming)
		_ = p.cl[1].Close()
		res := r.wait(p.s)
		if res.Outcome != OutcomeSucceeded || res.Confirmed != [2]bool{true, false} {
			t.Fatalf("result %+v", res)
		}
	})
	t.Run("unconfirmed fails", func(t *testing.T) {
		r := newRig(t)
		p := r.pair(SessionOptions{})
		p.punching()
		p.confirm(1, 1)
		p.state(StateConfirming)
		send(t, p.cl[0], simclient.Failure(p.s.ID(), protocol.RoleInitiator, protocol.ReasonHandoverTimeout, protocol.PhaseHandover))
		eventually(t, "final recorded", func() bool {
			p.s.mu.Lock()
			defer p.s.mu.Unlock()
			return p.s.st.finals[0] != nil
		})
		r.clk.Advance(3 * time.Second)
		res := r.wait(p.s)
		if res.Outcome != OutcomeSucceeded || res.Clients[0] == nil || res.Clients[0].Code != protocol.ReasonHandoverTimeout {
			t.Fatalf("result %+v", res)
		}
	})
	t.Run("negative linger", func(t *testing.T) {
		r := newRig(t, func(c *Config) { c.TTL.ConfirmLinger = -1 })
		p := r.pair(SessionOptions{})
		p.punching()
		p.confirm(0, 1)
		if res := r.wait(p.s); res.Outcome != OutcomeSucceeded {
			t.Fatalf("result %+v", res)
		}
	})
	t.Run("negative grace", func(t *testing.T) {
		r := newRig(t, func(c *Config) { c.TTL.ResultGrace = -1 })
		p := r.pair(SessionOptions{})
		p.punching()
		p.confirm(0, 1)
		p.confirm(1, 1)
		if res := r.wait(p.s); res.Outcome != OutcomeSucceeded || res.Confirmed != [2]bool{true, true} {
			t.Fatalf("result %+v", res)
		}
	})
	t.Run("punch_result confirms", func(t *testing.T) {
		r := newRig(t)
		p := r.pair(SessionOptions{})
		p.punching()
		p.succeed(0, 1)
		p.succeed(1, 1)
		if res := r.wait(p.s); res.Outcome != OutcomeSucceeded || res.Confirmed != [2]bool{true, true} {
			t.Fatalf("result %+v", res)
		}
	})
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

// TestControlLossDuringPunching: a side that loses its link while punching
// does not abort the other side; a confirmation still succeeds, otherwise the
// round deadline ends the session with control_interrupted.
func TestControlLossDuringPunching(t *testing.T) {
	t.Run("confirm", func(t *testing.T) {
		r := newRig(t)
		p := r.pair(SessionOptions{})
		p.punching()
		_ = p.cl[0].Close()
		eventually(t, "gone", func() bool {
			return p.s.Snapshot().State == StatePunching && func() bool {
				p.s.mu.Lock()
				defer p.s.mu.Unlock()
				return p.s.st.gone[0]
			}()
		})
		p.confirm(1, 1)
		p.state(StateConfirming)
		r.clk.Advance(3 * time.Second)
		res := r.wait(p.s)
		if res.Outcome != OutcomeSucceeded || res.Confirmed != [2]bool{false, true} {
			t.Fatalf("result %+v", res)
		}
	})
	t.Run("deadline", func(t *testing.T) {
		r := newRig(t)
		p := r.pair(SessionOptions{})
		p.punching()
		_ = p.cl[0].Close()
		eventually(t, "gone", func() bool {
			p.s.mu.Lock()
			defer p.s.mu.Unlock()
			return p.s.st.gone[0]
		})
		r.clk.Advance(10 * time.Second)
		a := expectAbort(t, p.cl[1])
		if a.By != protocol.RoleInitiator || a.Code != protocol.ReasonPeerOffline || a.Detail != detailControlInterrupted {
			t.Fatalf("abort %+v", a)
		}
		res := r.wait(p.s)
		if res.Code != protocol.ReasonControlInterrupted || res.Outcome != OutcomeAborted || res.FailedRole != protocol.RoleInitiator {
			t.Fatalf("result %+v", res)
		}
	})
	t.Run("both", func(t *testing.T) {
		r := newRig(t)
		p := r.pair(SessionOptions{})
		p.punching()
		_ = p.cl[0].Close()
		_ = p.cl[1].Close()
		if res := r.wait(p.s); res.Code != protocol.ReasonControlInterrupted {
			t.Fatalf("result %+v", res)
		}
	})
}

// TestClientFailureAbortsPeer: a client's punch_result{ok:false} aborts the
// other side with by = that side and its code.
func TestClientFailureAbortsPeer(t *testing.T) {
	for _, st := range []State{StateBinding, StateProbing, StateSummarized, StatePunching} {
		t.Run(string(st), func(t *testing.T) {
			r := newRig(t)
			s := r.session(SessionOptions{})
			p := &pair{r: r, s: s}
			p.cl[1] = r.attach(s, protocol.RoleResponder)
			p.starts[1] = expect[protocol.PunchStart](t, p.cl[1])
			if st != StateBinding {
				p.cl[0] = r.attach(s, protocol.RoleInitiator)
				p.starts[0] = expect[protocol.PunchStart](t, p.cl[0])
			}
			switch st {
			case StateSummarized:
				p.summaries()
			case StatePunching:
				p.punching()
			}
			send(t, p.cl[1], simclient.Failure(s.ID(), protocol.RoleResponder, protocol.ReasonProbeTimeout, protocol.PhaseProbing))
			if st != StateBinding {
				a := expectAbort(t, p.cl[0])
				if a.By != protocol.RoleResponder || a.Code != protocol.ReasonProbeTimeout {
					t.Fatalf("abort %+v", a)
				}
			}
			res := r.wait(s)
			if res.Code != protocol.ReasonProbeTimeout || res.FailedRole != protocol.RoleResponder || res.Outcome != OutcomeFailed {
				t.Fatalf("result %+v", res)
			}
		})
	}
}

// TestEarlyReject: no shared family and a transport conflict end the session
// right after the second report, with punch_abort{by: server}.
func TestEarlyReject(t *testing.T) {
	t.Run("no common family", func(t *testing.T) {
		r := newRig(t)
		p := r.pair(SessionOptions{})
		p.report(0)
		v6 := fam(1, simclient.OpenTraits)
		v6.Family = protocol.FamilyUDP6
		v6.Local = mustAP("[2001:db8::2]:5000")
		v6.Observed = []netip.AddrPort{mustAP("[2001:db8::2]:5000")}
		v6.Traits = simclient.OpenTraits(v6.Observed[0])
		v6.LocalAddrs = nil
		p.report(1, v6)
		for i := range 2 {
			a := expectAbort(t, p.cl[i])
			if a.By != protocol.RoleServer || a.Code != protocol.ReasonNoCommonFamily {
				t.Fatalf("abort %+v", a)
			}
		}
		if res := r.wait(p.s); res.Code != protocol.ReasonNoCommonFamily || res.Outcome != OutcomeFailed {
			t.Fatalf("result %+v", res)
		}
	})
	t.Run("transport", func(t *testing.T) {
		r := newRig(t)
		p := r.pair(SessionOptions{})
		p.report(0)
		send(t, p.cl[1], simclient.Report(*p.starts[1], 5, "kcp", fam(1, simclient.OpenTraits)))
		for i := range 2 {
			if a := expectAbort(t, p.cl[i]); a.Code != protocol.ReasonTransportMismatch {
				t.Fatalf("abort %+v", a)
			}
		}
		r.wait(p.s)
	})
	t.Run("fallback", func(t *testing.T) {
		r := newRig(t, func(c *Config) { c.TransportFallback = "kcp" })
		p := r.pair(SessionOptions{})
		p.report(0)
		send(t, p.cl[1], simclient.Report(*p.starts[1], 5, "tcp", fam(1, simclient.OpenTraits)))
		sum := expect[protocol.ProbeSummary](t, p.cl[0])
		if sum.Transport.Mode != "kcp" {
			t.Fatalf("transport %+v", sum.Transport)
		}
		p.s.Abort(protocol.ReasonCanceled, "")
		r.wait(p.s)
	})
}

// TestCoordinatorClose: sessions before punching get
// punch_abort{server_shutdown}; punching ones only lose their links; a
// confirming one keeps its confirmation.
func TestCoordinatorClose(t *testing.T) {
	r := newRig(t)
	binding := r.session(SessionOptions{})
	cb := r.attach(binding, protocol.RoleInitiator)
	expect[protocol.PunchStart](t, cb)
	punching := r.pair(SessionOptions{})
	punching.punching()
	confirming := r.pair(SessionOptions{})
	confirming.punching()
	confirming.confirm(0, 1)
	confirming.state(StateConfirming)
	idle := r.session(SessionOptions{})

	var wg sync.WaitGroup
	for range 20 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := r.c.Close(); err != nil {
				t.Error(err)
			}
		}()
	}
	if a := expectAbort(t, cb); a.Code != protocol.ReasonServerShutdown || a.By != protocol.RoleServer {
		t.Fatalf("abort %+v", a)
	}
	expectEOF(t, punching.cl[0])
	expectEOF(t, punching.cl[1])
	wg.Wait()
	if res := r.wait(binding); res.Code != protocol.ReasonServerShutdown {
		t.Fatalf("binding %+v", res)
	}
	if res := r.wait(punching.s); res.Code != protocol.ReasonServerShutdown {
		t.Fatalf("punching %+v", res)
	}
	if res := r.wait(confirming.s); res.Outcome != OutcomeSucceeded {
		t.Fatalf("confirming %+v", res)
	}
	if res := r.wait(idle); res.Code != protocol.ReasonServerShutdown {
		t.Fatalf("idle %+v", res)
	}
	if r.c.Len() != 0 {
		t.Fatalf("Len %d", r.c.Len())
	}
}

// TestParentCancel: the parent context's end aborts the session with
// canceled.
func TestParentCancel(t *testing.T) {
	r := newRig(t)
	parent, cancel := context.WithCancel(context.Background())
	p := r.pair(SessionOptions{Parent: parent})
	cancel()
	for i := range 2 {
		if a := expectAbort(t, p.cl[i]); a.Code != protocol.ReasonCanceled {
			t.Fatalf("abort %+v", a)
		}
	}
	res := r.wait(p.s)
	if res.Code != protocol.ReasonCanceled || !res.Retry.Retryable {
		t.Fatalf("result %+v", res)
	}
	if reasonOf(context.Cause(p.s.Context())) != protocol.ReasonCanceled {
		t.Fatalf("cause %v", context.Cause(p.s.Context()))
	}
	// A parent that is already done ends the session at once.
	done, cancel2 := context.WithCancel(context.Background())
	cancel2()
	s := r.session(SessionOptions{Parent: done})
	if res := r.wait(s); res.Code != protocol.ReasonCanceled {
		t.Fatalf("result %+v", res)
	}
}

// TestConcurrentAbort: concurrent Abort and Close calls end the session once
// with the first code and OnResult runs once.
func TestConcurrentAbort(t *testing.T) {
	r := newRig(t)
	p := r.pair(SessionOptions{})
	var wg sync.WaitGroup
	for i := range 100 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if i%10 == 0 {
				_ = r.c.Close()
				return
			}
			p.s.Abort(protocol.ReasonCanceled, "")
		}()
	}
	wg.Wait()
	r.wait(p.s)
	n := 0
	for {
		select {
		case <-r.results:
			n++
			continue
		default:
		}
		break
	}
	if n != 1 {
		t.Fatalf("OnResult %d times", n)
	}
}

// TestProgressNeverDrivesState: progress stages named confirmed or
// handover_done do not confirm anything.
func TestProgressNeverDrivesState(t *testing.T) {
	r := newRig(t, func(c *Config) { c.ObserveProgress = true })
	p := r.pair(SessionOptions{})
	p.punching()
	for i, stage := range []string{"confirmed", "handover_done"} {
		send(t, p.cl[0], &protocol.Progress{SessionID: p.s.ID(), Role: protocol.RoleInitiator, Seq: uint16(i + 1),
			Stage: stage, Status: protocol.StatusOK, Round: 1})
	}
	eventually(t, "timeline", func() bool { return p.s.Snapshot().LastStage[0] == "handover_done" })
	if snap := p.s.Snapshot(); snap.State != StatePunching || snap.Confirmed != [2]bool{} {
		t.Fatalf("snapshot %+v", snap)
	}
	p.s.Abort(protocol.ReasonCanceled, "")
	res := r.wait(p.s)
	if len(res.Timeline) != 2 || res.Timeline[1].Stage != "handover_done" {
		t.Fatalf("timeline %+v", res.Timeline)
	}
	if len(r.waitEvents(EvProgress, 2)) != 2 {
		t.Fatal("progress events")
	}
}

// TestSessionStartAndLookup covers the pre-generated starts and the index.
func TestSessionStartAndLookup(t *testing.T) {
	r := newRig(t)
	s := r.session(SessionOptions{SessionID: "abc-DEF_1", ClientKeys: [2]string{"vis", "prov"}})
	st := s.Start(protocol.RoleResponder)
	if st.SessionID != "abc-DEF_1" || st.Role != protocol.RoleResponder || st.Token.IsZero() || st.Policy == nil {
		t.Fatalf("start %+v", st)
	}
	st.Policy.Budget.MaxPackets = 1 // a copy
	if s.Start(protocol.RoleResponder).Policy.Budget.MaxPackets == 1 {
		t.Fatal("Start returned shared state")
	}
	if s.Start("x").SessionID != "" {
		t.Fatal("invalid role")
	}
	if got, ok := r.c.Lookup("abc-DEF_1"); !ok || got != s {
		t.Fatal("lookup")
	}
	if _, err := r.c.NewSession(SessionOptions{SessionID: "abc-DEF_1"}); !invalidArgument(err) {
		t.Fatalf("duplicate id: %v", err)
	}
	if _, err := r.c.NewSession(SessionOptions{SessionID: "bad id"}); !invalidArgument(err) {
		t.Fatalf("bad id: %v", err)
	}
	if _, err := r.c.NewSession(SessionOptions{Token: "short"}); !invalidArgument(err) {
		t.Fatalf("bad token: %v", err)
	}
	if _, err := r.c.NewSession(SessionOptions{Wire: protocol.WireSpec{PayloadMin: 10}}); !invalidArgument(err) {
		t.Fatalf("bad wire: %v", err)
	}
	tok := s.Start(protocol.RoleInitiator).Token
	text, _ := tok.MarshalText()
	s2 := r.session(SessionOptions{Token: string(text)})
	if s2.Start(protocol.RoleInitiator).Token != tok {
		t.Fatal("token option ignored")
	}
	if r.c.Len() != 2 || r.c.Stats().SessionsActive != 2 {
		t.Fatalf("Len %d", r.c.Len())
	}
	if r.c.Memory() == nil {
		t.Fatal("memory")
	}
}
