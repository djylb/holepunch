package coord

import (
	"sync"
	"testing"
	"time"

	"github.com/djylb/holepunch/coord/internal/simclient"
	"github.com/djylb/holepunch/internal/testkit"
	"github.com/djylb/holepunch/natprobe"
	"github.com/djylb/holepunch/plan"
	"github.com/djylb/holepunch/protocol"
)

func withRegistry(reg *natprobe.Registry) rigOpt {
	return func(c *Config) {
		c.Registry = reg
		c.NoObserver = false
	}
}

// TestDeadlines walks the bind and probe deadlines:
// the reason, the detail, the failed role, the notices, and the registry
// entry released.
func TestDeadlines(t *testing.T) {
	type abortWant struct {
		by   protocol.Role
		code protocol.Reason
	}
	cases := []struct {
		name    string
		attach  []int
		reports []int
		advance time.Duration
		code    protocol.Reason
		detail  string
		failed  protocol.Role
		aborts  map[int]abortWant
	}{
		{name: "created", advance: defBindTimeout, code: protocol.ReasonPeerOffline, detail: detailJoinTimeout},
		{name: "binding", attach: []int{0}, advance: defBindTimeout, code: protocol.ReasonPeerOffline,
			detail: detailJoinTimeout, failed: protocol.RoleResponder,
			aborts: map[int]abortWant{0: {protocol.RoleResponder, protocol.ReasonPeerOffline}}},
		{name: "probing", attach: []int{0, 1}, reports: []int{0}, advance: 5 * time.Second,
			code: protocol.ReasonProbeTimeout, failed: protocol.RoleResponder,
			aborts: map[int]abortWant{0: {protocol.RoleResponder, protocol.ReasonProbeTimeout}, 1: {protocol.RoleServer, protocol.ReasonProbeTimeout}}},
		{name: "probing none", attach: []int{1, 0}, advance: 5 * time.Second, code: protocol.ReasonProbeTimeout,
			aborts: map[int]abortWant{0: {protocol.RoleServer, protocol.ReasonProbeTimeout}, 1: {protocol.RoleServer, protocol.ReasonProbeTimeout}}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			reg := natprobe.NewRegistry(natprobe.RegistryConfig{})
			r := newRig(t, withRegistry(reg))
			s := r.session(SessionOptions{})
			if reg.Len() != 1 {
				t.Fatalf("registry %d", reg.Len())
			}
			p := &pair{r: r, s: s}
			for _, i := range c.attach {
				p.cl[i] = r.attach(s, roleOf(i))
				p.starts[i] = expect[protocol.PunchStart](t, p.cl[i])
			}
			for _, i := range c.reports {
				p.report(i)
				testkit.WaitFor(t, "report", func() bool { return s.Snapshot().Reported[i] })
			}
			r.clk.Advance(c.advance - time.Millisecond)
			if snap := s.Snapshot(); snap.State == StateClosed {
				t.Fatalf("closed early: %+v", snap)
			}
			r.clk.Advance(time.Millisecond)
			for i, w := range c.aborts {
				a := expectAbort(t, p.cl[i])
				if a.By != w.by || a.Reason != w.code {
					t.Fatalf("abort to %d: %+v, want %+v", i, a, w)
				}
			}
			res := r.wait(s)
			if res.Reason != c.code || res.Detail != c.detail || res.FailedRole != c.failed {
				t.Fatalf("result %+v", res)
			}
			if reg.Len() != 0 || r.c.Len() != 0 {
				t.Fatalf("registry %d sessions %d", reg.Len(), r.c.Len())
			}
		})
	}
}

// TestSummarizedDeadline: a side that does not get ready within
// ReadyTimeout ends the session with not_synchronized.
func TestSummarizedDeadline(t *testing.T) {
	r := newRig(t)
	p := r.pair(SessionOptions{})
	sums := p.summaries()
	send(t, p.cl[0], simclient.Ready(sums[0], protocol.RoleInitiator, 1))
	testkit.WaitFor(t, "ready", func() bool { return p.s.Snapshot().Ready[0] })
	r.clk.Advance(5 * time.Second)
	if a := expectAbort(t, p.cl[0]); a.By != protocol.RoleResponder || a.Reason != protocol.ReasonNotSynchronized {
		t.Fatalf("abort %+v", a)
	}
	if a := expectAbort(t, p.cl[1]); a.By != protocol.RoleServer {
		t.Fatalf("abort %+v", a)
	}
	res := r.wait(p.s)
	if res.Reason != protocol.ReasonNotSynchronized || res.FailedRole != protocol.RoleResponder || res.Outcome != OutcomeFailed {
		t.Fatalf("result %+v", res)
	}
}

// TestRoundDeadline: a round whose results do not arrive ends at its
// deadline (no_report) and the next round's go carries its plan.
func TestRoundDeadline(t *testing.T) {
	r := newRig(t)
	p := r.pair(SessionOptions{})
	gos := p.punching()
	next, ok := r.clk.Next()
	if !ok {
		t.Fatal("no timer")
	}
	window := time.Duration(gos[0].WindowMs) * time.Millisecond
	if d := next.Sub(r.clk.Now()); d < window || d > window+3*time.Second {
		t.Fatalf("round deadline in %v, window %v", d, window)
	}
	r.clk.AdvanceTo(next)
	for i := range 2 {
		g := expect[protocol.PunchGo](t, p.cl[i])
		if g.Round != 2 || g.Plan == nil || g.Plan.Round != 2 {
			t.Fatalf("go %+v", g)
		}
	}
	p.s.Abort(protocol.ReasonCanceled, "")
	res := r.wait(p.s)
	if len(res.Rounds) != 2 || res.Rounds[0].Class != plan.RoundNoReport {
		t.Fatalf("rounds %+v", res.Rounds)
	}
}

// TestPunchDeadline: the shared handshake deadline ends the punch with the
// attribution of both sides' evidence.
func TestPunchDeadline(t *testing.T) {
	r := newRig(t)
	to := protocol.Timeouts{HandshakeTimeoutMs: 2000}
	p := r.pair(SessionOptions{Timeouts: &to})
	p.punching()
	for range 8 {
		next, ok := r.clk.Next()
		if !ok {
			break
		}
		r.clk.AdvanceTo(next)
		if snap := p.s.Snapshot(); snap.State == StateClosed {
			break
		}
		testkit.WaitFor(t, "round planned", func() bool {
			p.s.mu.Lock()
			defer p.s.mu.Unlock()
			return !p.s.st.plan.planning
		})
	}
	res := r.wait(p.s)
	if res.Reason != protocol.ReasonNotSynchronized || res.Outcome != OutcomeFailed {
		t.Fatalf("result %+v", res)
	}
	if got := r.clk.Now().Sub(res.Timing.FirstGo); got > 3*time.Second {
		t.Fatalf("ended %v after the first go", got)
	}
}

// TestSessionExpired: the defensive lifetime cap ends a session no stage
// deadline ended.
func TestSessionExpired(t *testing.T) {
	r := newRig(t)
	p := r.pair(SessionOptions{})
	p.summaries()
	now := r.clk.Now()
	p.s.mu.Lock()
	p.s.st.expireAt = p.s.since(now) + time.Second
	p.s.rearmLocked(p.s.since(now))
	p.s.mu.Unlock()
	r.clk.Advance(time.Second)
	if a := expectAbort(t, p.cl[0]); a.Reason != protocol.ReasonSessionExpired {
		t.Fatalf("abort %+v", a)
	}
	if res := r.wait(p.s); res.Reason != protocol.ReasonSessionExpired || res.Outcome != OutcomeAborted {
		t.Fatalf("result %+v", res)
	}
}

// blockPlanner blocks Classify until released.
type blockPlanner struct {
	release chan struct{}
	entered chan struct{}
	once    sync.Once
}

func (b *blockPlanner) Classify(_ plan.ClassifyInput) plan.Classification {
	b.once.Do(func() { close(b.entered) })
	<-b.release
	return plan.Classification{}
}

func (b *blockPlanner) Round(_ plan.RoundInput) plan.RoundDecision { return plan.RoundDecision{} }

// TestPlannerBlockedDoesNotLeakResources: a planner that never returns does
// not keep the session: the probing deadline ends it with internal
// (planner_timeout) and releases the links, the registry entry and the
// quotas; Done waits for the planner to return.
func TestPlannerBlockedDoesNotLeakResources(t *testing.T) {
	bp := &blockPlanner{release: make(chan struct{}), entered: make(chan struct{})}
	r := newRig(t, func(c *Config) { c.Planner = bp })
	p := r.pair(SessionOptions{ClientKeys: [2]string{"a", "b"}})
	p.report(0)
	p.report(1)
	<-bp.entered
	r.clk.Advance(5 * time.Second)
	for i := range 2 {
		if a := expectAbort(t, p.cl[i]); a.Reason != protocol.ReasonInternal || a.Detail != detailPlannerTimeout {
			t.Fatalf("abort %+v", a)
		}
	}
	testkit.WaitFor(t, "released", func() bool { return r.c.Len() == 0 && r.c.Stats().ActiveByKey == 0 })
	select {
	case <-p.s.Done():
		t.Fatal("Done before the planner returned")
	default:
	}
	close(bp.release)
	res := r.wait(p.s)
	if res.Reason != protocol.ReasonInternal || res.Detail != detailPlannerTimeout {
		t.Fatalf("result %+v", res)
	}
}
