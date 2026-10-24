package coord

import (
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"github.com/djylb/holepunch/coord/internal/simclient"
	"github.com/djylb/holepunch/internal/faultconn"
	"github.com/djylb/holepunch/internal/life"
	"github.com/djylb/holepunch/internal/testkit"
	"github.com/djylb/holepunch/protocol"
)

// attachFault attaches role over a pipe whose server end is a faultconn.
func (r *rig) attachFault(s *Session, role protocol.Role) (*simclient.Client, *faultconn.Conn) {
	r.t.Helper()
	srv, cli := net.Pipe()
	fc := faultconn.Wrap(srv)
	if err := s.Attach(role, fc, AttachOptions{Security: protocol.ControlSecurityInsecureForTesting}); err != nil {
		r.t.Fatal(err)
	}
	// No pong: a Release of the client must not race its own writes.
	c, err := simclient.New(cli, role, simclient.Options{Now: r.clk.Now, NoPong: true})
	if err != nil {
		r.t.Fatal(err)
	}
	r.t.Cleanup(func() { _ = c.Close() })
	return c, fc
}

// releaseIdle releases the client's link once the ping sent with
// punch_start has been read: a Release in the middle of that frame fails.
func releaseIdle(t *testing.T, c *simclient.Client) (net.Conn, error) {
	t.Helper()
	testkit.WaitFor(t, "ping #1 read", func() bool { return c.Pings() >= 1 })
	return c.Release()
}

// matrixPair builds a session in state st with the initiator on a faultconn.
func (r *rig) matrixPair(st State) (*pair, *faultconn.Conn) {
	r.t.Helper()
	opts := readyGated()
	opts.ClientKeys = [2]string{"vis", "prov"}
	p := &pair{r: r, s: r.session(opts)}
	var fc *faultconn.Conn
	p.cl[0], fc = r.attachFault(p.s, protocol.RoleInitiator)
	p.starts[0] = expect[protocol.PunchStart](r.t, p.cl[0])
	if st == StateBinding {
		return p, fc
	}
	p.cl[1] = r.attach(p.s, protocol.RoleResponder)
	p.starts[1] = expect[protocol.PunchStart](r.t, p.cl[1])
	switch st {
	case StateSummarized:
		p.summaries()
	case StatePunching:
		p.punching()
	case StateConfirming:
		p.punching()
		p.confirm(1, 1)
		p.state(StateConfirming)
	}
	return p, fc
}

// TestServerFaultMatrix runs the coordinator's fault matrix: every cell
// ends with the expected code, releases
// everything, calls OnResult once and tells the other side by
// punch_abort or EOF.
func TestServerFaultMatrix(t *testing.T) {
	type cell struct {
		code    protocol.Reason
		success bool
		abort   bool // the responder gets a punch_abort (else only EOF)
	}
	faults := []struct {
		name  string
		apply func(r *rig, p *pair, fc *faultconn.Conn)
		want  map[State]cell
	}{
		{"disconnect", func(r *rig, p *pair, fc *faultconn.Conn) { _ = p.cl[0].Close() }, map[State]cell{
			StateBinding:    {code: protocol.ReasonPeerOffline},
			StateProbing:    {code: protocol.ReasonPeerOffline, abort: true},
			StateSummarized: {code: protocol.ReasonPeerOffline, abort: true},
			StatePunching:   {code: protocol.ReasonControlInterrupted, abort: true},
			StateConfirming: {success: true},
		}},
		{"write error", func(r *rig, p *pair, fc *faultconn.Conn) {
			fc.FailWrites(errors.New("broken"))
			pingNow(r, p)
		}, map[State]cell{
			StateBinding:    {code: protocol.ReasonPeerOffline},
			StateProbing:    {code: protocol.ReasonPeerOffline, abort: true},
			StateSummarized: {code: protocol.ReasonPeerOffline, abort: true},
			StatePunching:   {code: protocol.ReasonControlInterrupted, abort: true},
			StateConfirming: {success: true},
		}},
		{"malformed", func(r *rig, p *pair, fc *faultconn.Conn) {
			nc, err := releaseIdle(r.t, p.cl[0])
			if err != nil {
				r.t.Fatal(err)
			}
			go func() { _, _ = io.Copy(io.Discard, nc) }()
			_, _ = nc.Write([]byte{'h', 'p', 1, 2, 0, 0, 0, 2, '{'})
			_ = nc.Close()
		}, map[State]cell{
			StateBinding:    {code: protocol.ReasonPeerOffline},
			StateProbing:    {code: protocol.ReasonPeerOffline, abort: true},
			StateSummarized: {code: protocol.ReasonPeerOffline, abort: true},
			StatePunching:   {code: protocol.ReasonControlInterrupted, abort: true},
			StateConfirming: {success: true},
		}},
		{"garbage", func(r *rig, p *pair, fc *faultconn.Conn) {
			nc, err := releaseIdle(r.t, p.cl[0])
			if err != nil {
				r.t.Fatal(err)
			}
			go func() { _, _ = io.Copy(io.Discard, nc) }()
			_, _ = nc.Write([]byte("GET / HTTP/1.0\r\n\r\n"))
		}, map[State]cell{
			StateBinding:    {code: protocol.ReasonProtocolViolation},
			StateProbing:    {code: protocol.ReasonProtocolViolation, abort: true},
			StateSummarized: {code: protocol.ReasonProtocolViolation, abort: true},
			StatePunching:   {code: protocol.ReasonProtocolViolation, abort: true},
			StateConfirming: {success: true},
		}},
		{"bad origin", func(r *rig, p *pair, fc *faultconn.Conn) {
			send(r.t, p.cl[0], protocol.Progress{SessionID: "someone-else", Role: protocol.RoleInitiator, Stage: "x"})
		}, map[State]cell{
			StateBinding:    {code: protocol.ReasonProtocolViolation},
			StateProbing:    {code: protocol.ReasonProtocolViolation, abort: true},
			StateSummarized: {code: protocol.ReasonProtocolViolation, abort: true},
			StatePunching:   {code: protocol.ReasonProtocolViolation, abort: true},
			StateConfirming: {success: true},
		}},
		{"close", func(r *rig, p *pair, fc *faultconn.Conn) { _ = r.c.Close() }, map[State]cell{
			StateBinding:    {code: protocol.ReasonServerShutdown},
			StateProbing:    {code: protocol.ReasonServerShutdown, abort: true},
			StateSummarized: {code: protocol.ReasonServerShutdown, abort: true},
			StatePunching:   {code: protocol.ReasonServerShutdown},
			StateConfirming: {success: true},
		}},
		{"abort", func(r *rig, p *pair, fc *faultconn.Conn) { p.s.Abort(protocol.ReasonCanceled, "x") }, map[State]cell{
			StateBinding:    {code: protocol.ReasonCanceled},
			StateProbing:    {code: protocol.ReasonCanceled, abort: true},
			StateSummarized: {code: protocol.ReasonCanceled, abort: true},
			StatePunching:   {code: protocol.ReasonCanceled, abort: true},
			StateConfirming: {code: protocol.ReasonCanceled},
		}},
	}
	states := []State{StateBinding, StateProbing, StateSummarized, StatePunching, StateConfirming}
	for _, f := range faults {
		for _, st := range states {
			want := f.want[st]
			t.Run(f.name+"/"+string(st), func(t *testing.T) {
				r := newRig(t)
				p, fc := r.matrixPair(st)
				f.apply(r, p, fc)
				if st == StatePunching && want.code == protocol.ReasonControlInterrupted {
					testkit.WaitFor(t, "gone", func() bool {
						p.s.mu.Lock()
						defer p.s.mu.Unlock()
						return p.s.st.gone[0]
					})
					r.clk.Advance(10 * time.Second)
				}
				if p.cl[1] != nil {
					if want.abort {
						if a := expectAbort(t, p.cl[1]); a.Reason != want.code && a.Reason != protocol.ReasonPeerOffline {
							t.Fatalf("abort %+v", a)
						}
					} else {
						expectEOF(t, p.cl[1])
					}
				}
				res := r.wait(p.s)
				if want.success != (res.Outcome == OutcomeSucceeded) || !want.success && res.Reason != want.code {
					t.Fatalf("result %+v, want %+v", res, want)
				}
				if r.c.Len() != 0 || r.c.Stats().ActiveByKey != 0 {
					t.Fatalf("not released: len %d stats %+v", r.c.Len(), r.c.Stats())
				}
				select {
				case <-r.results:
				case <-time.After(testkit.WaitBound(t)):
					t.Fatal("no OnResult")
				}
				select {
				case extra := <-r.results:
					t.Fatalf("second OnResult %+v", extra)
				default:
				}
			})
		}
	}
}

// pingNow makes the server write to the initiator's link: the next ping is
// due right away.
func pingNow(r *rig, p *pair) {
	r.clk.Advance(time.Millisecond) // session time 0 would read as "no ping due"
	p.s.mu.Lock()
	l := p.s.st.links[0]
	if l != nil && !l.dead {
		now := p.s.since(r.clk.Now())
		l.ping.inPhase = [2]uint8{}
		l.ping.due = now
		p.s.rearmLocked(now)
	}
	p.s.mu.Unlock()
	r.clk.Advance(0)
}

// TestStalledPeerBounded: a client that stops reading loses its link to the
// write timeout; the other side is told.
func TestStalledPeerBounded(t *testing.T) {
	r := newRig(t, func(c *Config) { c.Limits.WriteTimeout = 200 * time.Millisecond })
	p := r.noPongPair()
	nc, err := releaseIdle(t, p.cl[0])
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = nc.Close() }()
	pingNow(r, p)
	start := time.Now()
	if a := expectAbort(t, p.cl[1]); a.By != protocol.RoleInitiator || a.Reason != protocol.ReasonPeerOffline {
		t.Fatalf("abort %+v", a)
	}
	res := r.wait(p.s)
	if res.Detail != detailWriteTimeout || time.Since(start) > time.Second {
		t.Fatalf("result %+v after %v", res, time.Since(start))
	}
}

// TestStalledQueue: a link whose write queue is full is lost with detail
// stalled.
func TestStalledQueue(t *testing.T) {
	r := newRig(t)
	s := r.session(SessionOptions{})
	c, fc := r.attachFault(s, protocol.RoleInitiator)
	expect[protocol.PunchStart](t, c)
	fc.BlockWrites()
	for range 20 {
		s.mu.Lock()
		fx := s.sendPingLocked(0)
		s.mu.Unlock()
		s.apply(fx)
		if fx.term != nil || fx.sendErr[0] != nil {
			break
		}
		s.mu.Lock()
		s.st.links[0].ping.sent = 0
		s.mu.Unlock()
	}
	res := r.wait(s)
	if res.Reason != protocol.ReasonPeerOffline || res.Detail != detailStalled {
		t.Fatalf("result %+v", res)
	}
}

// TestStalledRearmsFromNow: a link lost to a full write queue while punching
// re-arms the session timer from the clock's now, not from the session's last
// update, so the round's deadline ends the session on time.
func TestStalledRearmsFromNow(t *testing.T) {
	r := newRig(t)
	p := r.pair(SessionOptions{})
	p.punching()
	p.s.mu.Lock()
	left := p.s.st.rounds.cur.deadline - p.s.since(r.clk.Now())
	p.s.mu.Unlock()
	// Time passes without an update, as when a round's deadline ended it and
	// the next round's go stalls.
	r.clk.Advance(left / 2)
	p.s.apply(p.s.stalled(0))
	r.clk.Advance(left - left/2)
	if res := r.wait(p.s); res.Reason != protocol.ReasonControlInterrupted || res.FailedRole != protocol.RoleInitiator {
		t.Fatalf("result %+v", res)
	}
}

// panickyErr is a connection's write error whose Is and As methods panic:
// examining it runs caller code.
type panickyErr struct{}

func (panickyErr) Error() string   { return "panicky" }
func (panickyErr) Is(_ error) bool { panic("is") }
func (panickyErr) As(_ any) bool   { panic("as") }

// TestPanickyConnError: a link whose connection fails with an error that
// panics when examined is lost like any other — peer_offline, the other side
// told — because the coordinator examines such errors outside the session
// mutex and in a recover boundary; the panics are counted.
func TestPanickyConnError(t *testing.T) {
	r := newRig(t)
	p, fc := r.matrixPair(StateProbing)
	fc.FailWrites(panickyErr{})
	pingNow(r, p)
	if a := expectAbort(t, p.cl[1]); a.By != protocol.RoleInitiator || a.Reason != protocol.ReasonPeerOffline {
		t.Fatalf("abort %+v", a)
	}
	res := r.wait(p.s)
	if res.Reason != protocol.ReasonPeerOffline || res.FailedRole != protocol.RoleInitiator {
		t.Fatalf("result %+v", res)
	}
	if r.c.Stats().Panics == 0 {
		t.Fatal("panic not counted")
	}
}

// TestCallbackPanics: panicking Observer and OnResult callbacks are counted
// and change nothing else.
func TestCallbackPanics(t *testing.T) {
	r := newRig(t, func(c *Config) {
		c.Observer = func(Event) { panic("observer") }
		c.OnResult = func(Result) { panic("on result") }
	})
	p := r.pair(SessionOptions{})
	p.s.Abort(protocol.ReasonCanceled, "")
	res := r.wait(p.s)
	if res.Reason != protocol.ReasonCanceled {
		t.Fatalf("result %+v", res)
	}
	testkit.WaitFor(t, "panics counted", func() bool { return r.c.Stats().Panics >= 2 })
}

// TestObserverReentrant: an Observer may call back into the coordinator.
func TestObserverReentrant(t *testing.T) {
	var r *rig
	seen := make(chan struct{}, 1)
	r = newRig(t, func(c *Config) {
		c.Observer = func(ev Event) {
			if s, ok := r.c.Lookup(ev.SessionID); ok {
				s.Snapshot()
			}
			_ = r.c.Stats()
			select {
			case seen <- struct{}{}:
			default:
			}
		}
	})
	p := r.pair(SessionOptions{})
	<-seen
	p.s.Abort(protocol.ReasonCanceled, "")
	r.wait(p.s)
}

// TestObserverQueueBounded: a slow Observer loses events, counted, and
// never blocks the sessions.
func TestObserverQueueBounded(t *testing.T) {
	block := make(chan struct{})
	r := newRig(t, func(c *Config) {
		c.Limits.ObserverQueue = 1
		c.Observer = func(Event) { <-block }
	})
	for range 5 {
		s := r.session(SessionOptions{})
		s.Abort(protocol.ReasonCanceled, "")
		r.wait(s)
	}
	close(block)
	if r.c.Stats().EventsDropped == 0 {
		t.Fatal("no event dropped")
	}
}

// TestCloseTimeout: a session stuck in user code makes Close give up after
// 3 s with ErrShutdownTimeout and count it. A panic in the same shutdown
// hides neither failure: Close returns both, the panic first.
func TestCloseTimeout(t *testing.T) {
	if testing.Short() {
		t.Skip("3 s")
	}
	bp := &blockPlanner{release: make(chan struct{}), entered: make(chan struct{})}
	r := newRig(t, func(c *Config) { c.Planner = bp })
	p := r.pair(SessionOptions{})
	p.report(0)
	p.report(1)
	<-bp.entered
	panicAfterCancel(r.c)
	err := r.c.Close()
	var pe *life.PanicError
	if !errors.Is(err, ErrShutdownTimeout) || !errors.As(err, &pe) || pe.Where() != fiClose {
		t.Fatalf("close: %v", err)
	}
	if st := r.c.Stats(); st.Stuck != 1 || st.Panics != 1 {
		t.Fatalf("stuck %d, panics %d", st.Stuck, st.Panics)
	}
	if again := r.c.Close(); !errors.Is(again, err) {
		t.Fatalf("second close: %v, want %v", again, err)
	}
	close(bp.release)
	r.wait(p.s)
}

// TestHousekeeping: every 10 s the housekeeping sweeps the quota table, the
// strategy memory and the Registry.
func TestHousekeeping(t *testing.T) {
	r := newRig(t)
	s := r.session(SessionOptions{ClientKeys: [2]string{"a", ""}})
	s.Abort(protocol.ReasonCanceled, "")
	r.wait(s)
	for range 15 {
		// Wait for the housekeeping goroutine to re-arm its timer.
		if err := r.clk.WaitPending(ctx(t), 1); err != nil {
			t.Fatal(err)
		}
		r.clk.Advance(housekeepEvery)
	}
	testkit.WaitFor(t, "key entry swept", func() bool { return r.c.Stats().KeyEntries == 0 })
}
