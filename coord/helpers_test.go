package coord

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"go.uber.org/goleak"

	"github.com/djylb/holepunch/clock"
	"github.com/djylb/holepunch/coord/internal/simclient"
	"github.com/djylb/holepunch/protocol"
)

func TestMain(m *testing.M) { goleak.VerifyTestMain(m) }

// Addresses of the scripted clients (documentation ranges, global scope).
var (
	pubI   = netip.MustParseAddrPort("203.0.113.10:40000")
	pubR   = netip.MustParseAddrPort("198.51.100.20:50000")
	localI = netip.MustParseAddrPort("192.168.1.10:40000")
	localR = netip.MustParseAddrPort("10.0.0.20:50000")
)

const waitLimit = 5 * time.Second

var mustAP = netip.MustParseAddrPort

// rig is a coordinator under test with a fake clock and a channel of
// results.
type rig struct {
	t       *testing.T
	clk     *clock.Fake
	c       *Coordinator
	results chan Result

	evMu   sync.Mutex
	events []Event
}

type rigOpt func(*Config)

func newRig(t *testing.T, opts ...rigOpt) *rig {
	t.Helper()
	r := &rig{t: t, clk: clock.NewFake(t, time.Time{}), results: make(chan Result, 64)}
	cfg := Config{
		NoObserver: true,
		Clock:      r.clk,
		OnResult:   func(res Result) { r.results <- res },
		Observer: func(ev Event) {
			r.evMu.Lock()
			r.events = append(r.events, ev)
			r.evMu.Unlock()
		},
	}
	for _, o := range opts {
		o(&cfg)
	}
	c, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	r.c = c
	t.Cleanup(func() { _ = c.Close() })
	return r
}

func (r *rig) session(opts SessionOptions) *Session {
	r.t.Helper()
	s, err := r.c.NewSession(opts)
	if err != nil {
		r.t.Fatal(err)
	}
	return s
}

// attach attaches a scripted client for role over a pipe.
func (r *rig) attach(s *Session, role protocol.Role, o ...simclient.Options) *simclient.Client {
	r.t.Helper()
	srv, cli := net.Pipe()
	if err := s.Attach(role, srv, AttachOptions{Security: protocol.ControlSecurityInsecureForTesting}); err != nil {
		r.t.Fatal(err)
	}
	opt := simclient.Options{Now: r.clk.Now}
	if len(o) > 0 {
		opt = o[0]
		if opt.Now == nil {
			opt.Now = r.clk.Now
		}
	}
	c, err := simclient.New(cli, role, opt)
	if err != nil {
		r.t.Fatal(err)
	}
	r.t.Cleanup(func() { _ = c.Close() })
	return c
}

func ctx(t *testing.T) context.Context {
	c, cancel := context.WithTimeout(context.Background(), waitLimit)
	t.Cleanup(cancel)
	return c
}

// wait returns the session's Result once Done closes.
func (r *rig) wait(s *Session) Result {
	r.t.Helper()
	select {
	case <-s.Done():
	case <-time.After(waitLimit):
		r.t.Fatalf("session %s not done: %+v", s.ID(), s.Snapshot())
	}
	res, ok := s.Result()
	if !ok {
		r.t.Fatal("no result after Done")
	}
	return res
}

// eventually polls cond in real time.
func eventually(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(waitLimit)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timeout waiting for %s", what)
		}
		time.Sleep(time.Millisecond)
	}
}

func expect[T any](t *testing.T, c *simclient.Client) *T {
	t.Helper()
	m, err := simclient.Expect[T](ctx(t), c)
	if err != nil {
		t.Fatalf("%s: %v", c.Role, err)
	}
	return m
}

func send(t *testing.T, c *simclient.Client, m protocol.Message) {
	t.Helper()
	if err := c.Send(ctx(t), m); err != nil {
		t.Fatalf("%s send %T: %v", c.Role, m, err)
	}
}

// expectAbort reads until a punch_abort arrives (other frames are skipped).
func expectAbort(t *testing.T, c *simclient.Client) *protocol.Abort {
	t.Helper()
	for {
		m, _, err := c.Next(ctx(t))
		if err != nil {
			t.Fatalf("%s: no abort: %v", c.Role, err)
		}
		if a, ok := m.(*protocol.Abort); ok {
			return a
		}
	}
}

// expectEOF reads until the link closes, failing on a punch_abort.
func expectEOF(t *testing.T, c *simclient.Client) {
	t.Helper()
	for {
		m, _, err := c.Next(ctx(t))
		if err != nil {
			if errors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("%s: link not closed", c.Role)
			}
			return
		}
		if a, ok := m.(*protocol.Abort); ok {
			t.Fatalf("%s: unexpected abort %+v", c.Role, a)
		}
	}
}

// pair is a session with both clients attached and their starts read.
type pair struct {
	r      *rig
	s      *Session
	cl     [2]*simclient.Client
	starts [2]*protocol.PunchStart
}

func (r *rig) pair(opts SessionOptions) *pair {
	r.t.Helper()
	p := &pair{r: r, s: r.session(opts)}
	for i := range 2 {
		p.cl[i] = r.attach(p.s, roleOf(i))
		p.starts[i] = expect[protocol.PunchStart](r.t, p.cl[i])
	}
	return p
}

// fam is the default scripted family of side i: open NAT, one observer.
func fam(i int, traits func(netip.AddrPort) protocol.Traits) simclient.Family {
	pub, local := pubI, localI
	if i == 1 {
		pub, local = pubR, localR
	}
	return simclient.Family{Family: protocol.FamilyUDP4, Local: local, Observed: []netip.AddrPort{pub},
		Traits: traits(pub), LocalAddrs: []netip.Addr{local.Addr()}}
}

// report sends side i's probe_report.
func (p *pair) report(i int, fams ...simclient.Family) {
	p.r.t.Helper()
	if len(fams) == 0 {
		fams = []simclient.Family{fam(i, simclient.OpenTraits)}
	}
	send(p.r.t, p.cl[i], simclient.Report(*p.starts[i], 5, "quic", fams...))
}

// summaries reports both sides (default families) and reads both summaries.
func (p *pair) summaries() [2]*protocol.ProbeSummary {
	p.r.t.Helper()
	p.report(0)
	p.report(1)
	var out [2]*protocol.ProbeSummary
	for i := range 2 {
		out[i] = expect[protocol.ProbeSummary](p.r.t, p.cl[i])
	}
	return out
}

// punching runs the session to round 1 and returns both go frames.
func (p *pair) punching() [2]*protocol.PunchGo {
	p.r.t.Helper()
	sums := p.summaries()
	for i := range 2 {
		send(p.r.t, p.cl[i], simclient.Ready(sums[i], roleOf(i), 3))
	}
	var out [2]*protocol.PunchGo
	for i := range 2 {
		out[i] = expect[protocol.PunchGo](p.r.t, p.cl[i])
	}
	return out
}

func (p *pair) path(i int, round uint8) *protocol.PathInfo {
	if i == 0 {
		return simclient.Path(protocol.FamilyUDP4, localI, pubR, round)
	}
	return simclient.Path(protocol.FamilyUDP4, localR, pubI, round)
}

// confirm sends side i's round_result{confirmed}.
func (p *pair) confirm(i int, round uint8) {
	p.r.t.Helper()
	send(p.r.t, p.cl[i], simclient.Confirmed(p.s.ID(), roleOf(i), round, p.path(i, round)))
}

// succeed sends side i's punch_result{ok}.
func (p *pair) succeed(i int, round uint8) {
	p.r.t.Helper()
	send(p.r.t, p.cl[i], simclient.Success(p.s.ID(), roleOf(i), p.path(i, round)))
}

// windowEnd sends side i's round_result{window_end} with the outcome.
func (p *pair) windowEnd(i int, round uint8, o simclient.Outcome) {
	p.r.t.Helper()
	if o.Family == "" {
		o.Family = protocol.FamilyUDP4
	}
	send(p.r.t, p.cl[i], simclient.RoundEnd(p.s.ID(), roleOf(i), round, protocol.RoundWindowEnd, o))
}

// state waits until the session reaches st.
func (p *pair) state(st State) {
	p.r.t.Helper()
	eventually(p.r.t, string(st), func() bool { return p.s.Snapshot().State == st })
}

// eventsOf returns the events of kind k delivered so far.
func (r *rig) eventsOf(k EventKind) []Event {
	r.evMu.Lock()
	defer r.evMu.Unlock()
	var out []Event
	for _, ev := range r.events {
		if ev.Kind == k {
			out = append(out, ev)
		}
	}
	return out
}

// waitEvents waits until n events of kind k were delivered and returns them.
func (r *rig) waitEvents(k EventKind, n int) []Event {
	r.t.Helper()
	eventually(r.t, k.String()+" events", func() bool { return len(r.eventsOf(k)) >= n })
	return r.eventsOf(k)
}

// waitCounters waits until the session's counters satisfy cond.
func (p *pair) waitCounters(cond func(Counters) bool) {
	p.r.t.Helper()
	eventually(p.r.t, "counters", func() bool {
		p.s.mu.Lock()
		defer p.s.mu.Unlock()
		return cond(p.s.st.ctr)
	})
}

// netPipe returns both ends of a pipe, closed at the end of the test.
func netPipe(t *testing.T) (net.Conn, net.Conn) {
	a, b := net.Pipe()
	t.Cleanup(func() {
		_ = a.Close()
		_ = b.Close()
	})
	return a, b
}

// expectEOFOrAbort reads until the link closes.
func expectEOFOrAbort(t *testing.T, c *simclient.Client) {
	t.Helper()
	for {
		if _, _, err := c.Next(ctx(t)); err != nil {
			if errors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("%s: link not closed", c.Role)
			}
			return
		}
	}
}

// noPongPair is a pair whose initiator does not answer pings, so that a
// Release of it never races its own writes.
func (r *rig) noPongPair() *pair {
	r.t.Helper()
	p := &pair{r: r, s: r.session(SessionOptions{})}
	p.cl[0] = r.attach(p.s, protocol.RoleInitiator, simclient.Options{NoPong: true})
	p.starts[0] = expect[protocol.PunchStart](r.t, p.cl[0])
	p.cl[1] = r.attach(p.s, protocol.RoleResponder)
	p.starts[1] = expect[protocol.PunchStart](r.t, p.cl[1])
	return p
}

// expectOneResult returns the one OnResult call of a session and checks
// that no second one follows.
func expectOneResult(t *testing.T, r *rig) Result {
	t.Helper()
	var res Result
	select {
	case res = <-r.results:
	case <-time.After(waitLimit):
		t.Fatal("no OnResult")
	}
	select {
	case again := <-r.results:
		t.Fatalf("second OnResult: %+v", again)
	case <-time.After(20 * time.Millisecond):
	}
	return res
}

// invalidArgument reports whether err is a *protocol.ValidationError with
// reason invalid_argument.
func invalidArgument(err error) bool {
	var ve *protocol.ValidationError
	return errors.As(err, &ve) && ve.Reason == protocol.ReasonInvalidArgument
}

// reasonOf is the reason of the *ReasonError in err's chain, or "".
func reasonOf(err error) protocol.Reason {
	var re *ReasonError
	if errors.As(err, &re) {
		return re.Reason
	}
	return ""
}
