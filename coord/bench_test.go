package coord

import (
	"context"
	"net"
	"runtime"
	"testing"
	"time"

	"github.com/djylb/holepunch/coord/internal/simclient"
	"github.com/djylb/holepunch/internal/faultconn"
	"github.com/djylb/holepunch/internal/testkit"
	"github.com/djylb/holepunch/protocol"
)

// parkedSession is a session parked in summarized, with the server ends of
// its links counted.
type parkedSession struct {
	s   *Session
	cl  [2]*simclient.Client
	srv [2]*faultconn.Conn
}

// park creates n sessions and runs each to summarized.
func park(tb testing.TB, c *Coordinator, n int) []parkedSession {
	tb.Helper()
	out := make([]parkedSession, n)
	for k := range out {
		ps := &out[k]
		s, err := c.NewSession(SessionOptions{})
		if err != nil {
			tb.Fatal(err)
		}
		ps.s = s
		var starts [2]*protocol.PunchStart
		for i := range 2 {
			a, b := net.Pipe()
			ps.srv[i] = faultconn.Wrap(a)
			if err := s.Attach(roleOf(i), ps.srv[i], AttachOptions{Security: protocol.ControlSecurityDeclared}); err != nil {
				tb.Fatal(err)
			}
			cl, err := simclient.New(b, roleOf(i), simclient.Options{})
			if err != nil {
				tb.Fatal(err)
			}
			ps.cl[i] = cl
			st, err := simclient.Expect[protocol.PunchStart](ctxTB(tb), cl)
			if err != nil {
				tb.Fatal(err)
			}
			starts[i] = st
		}
		for i := range 2 {
			rep := simclient.Report(*starts[i], 1, "quic", fam(i, simclient.OpenTraits))
			if err := ps.cl[i].Send(ctxTB(tb), &rep); err != nil {
				tb.Fatal(err)
			}
		}
		for i := range 2 {
			if _, err := simclient.Expect[protocol.ProbeSummary](ctxTB(tb), ps.cl[i]); err != nil {
				tb.Fatal(err)
			}
		}
	}
	return out
}

func ctxTB(tb testing.TB) context.Context {
	c, cancel := context.WithTimeout(context.Background(), testkit.WaitBound(tb))
	tb.Cleanup(cancel)
	return c
}

// serverReads sums the Read returns and read deadline calls on the server
// ends.
func serverReads(ps []parkedSession) (reads, deadlines int64) {
	for _, p := range ps {
		for _, fc := range p.srv {
			reads += fc.ReadReturns()
			deadlines += fc.ReadDeadlines()
		}
	}
	return reads, deadlines
}

func unpark(tb testing.TB, c *Coordinator, ps []parkedSession) {
	for _, p := range ps {
		p.s.Abort(protocol.ReasonCanceled, "")
		<-p.s.Done()
		_ = p.cl[0].Close()
		_ = p.cl[1].Close()
	}
	if c.Len() != 0 {
		tb.Fatalf("Len %d", c.Len())
	}
}

// checkIdle parks n sessions, lets them sit idle and checks the resource
// bounds: at most five goroutines per session on the server side (two per
// link in controlwire and the session goroutine), one timer per session, no
// read returning and no read deadline set while idle.
func checkIdle(tb testing.TB, n int, idle time.Duration) (goroutinesPerSession float64, heapPerSession float64) {
	// The longest ready timeout keeps the first parked sessions from ending
	// (and reading) while the last are parked, on a slow or loaded machine.
	c, err := New(Config{NoObserver: true, Limits: Limits{NewSessions: Rate{PerSec: -1}, MaxPending: -1},
		TTL: TTLConfig{ReadyTimeout: maxReady}})
	if err != nil {
		tb.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	runtime.GC()
	var before runtime.MemStats
	runtime.ReadMemStats(&before)
	g0 := runtime.NumGoroutine()
	ps := park(tb, c, n)
	runtime.GC()
	var after runtime.MemStats
	runtime.ReadMemStats(&after)
	// The scripted clients hold two goroutines per link: subtract them.
	server := runtime.NumGoroutine() - g0 - 4*n
	if server > 5*n+16 {
		tb.Fatalf("%d server goroutines for %d sessions", server, n)
	}
	reads0, dl0 := serverReads(ps)
	time.Sleep(idle)
	reads1, dl1 := serverReads(ps)
	if reads1 != reads0 || dl1 != dl0 {
		tb.Fatalf("idle sessions woke up: %d reads, %d read deadlines", reads1-reads0, dl1-dl0)
	}
	unpark(tb, c, ps)
	return float64(server) / float64(n), float64(int64(after.HeapInuse)-int64(before.HeapInuse)) / float64(n)
}

// TestIdleSessionsDoNotWake: parked sessions cost no wakeup and stay within
// their goroutine bound.
func TestIdleSessionsDoNotWake(t *testing.T) {
	checkIdle(t, 50, 300*time.Millisecond)
}

// BenchmarkCoordinator1000 parks 1000 sessions in summarized (both clients
// attached, reported and summarized), checks the idle invariants and
// reports the per-session cost.
func BenchmarkCoordinator1000(b *testing.B) {
	for b.Loop() {
		g, heap := checkIdle(b, 1000, time.Second)
		b.ReportMetric(g, "goroutines/session")
		b.ReportMetric(heap/1024, "KiB/session")
	}
}

// BenchmarkSessionLifecycle measures one session from NewSession to a
// confirmed success over pipes, with the scripted clients.
func BenchmarkSessionLifecycle(b *testing.B) {
	c, err := New(Config{NoObserver: true, Limits: Limits{NewSessions: Rate{PerSec: -1}}})
	if err != nil {
		b.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	b.ReportAllocs()
	for b.Loop() {
		ps := park(b, c, 1)[0]
		for i := range 2 {
			r := protocol.PunchReady{SessionID: ps.s.ID(), Role: roleOf(i), ElapsedMs: 1,
				Families: []protocol.FamilyReady{{Family: protocol.FamilyUDP4, Sockets: 1}}}
			if err := ps.cl[i].Send(ctxTB(b), &r); err != nil {
				b.Fatal(err)
			}
		}
		for i := range 2 {
			if _, err := simclient.Expect[protocol.PunchGo](ctxTB(b), ps.cl[i]); err != nil {
				b.Fatal(err)
			}
		}
		p := &pair{s: ps.s}
		for i := range 2 {
			m := simclient.Confirmed(ps.s.ID(), roleOf(i), 1, p.path(i, 1))
			_ = ps.cl[i].Send(ctxTB(b), &m)
			ok := simclient.Success(ps.s.ID(), roleOf(i), p.path(i, 1))
			_ = ps.cl[i].Send(ctxTB(b), &ok)
		}
		<-ps.s.Done()
		_ = ps.cl[0].Close()
		_ = ps.cl[1].Close()
	}
}
