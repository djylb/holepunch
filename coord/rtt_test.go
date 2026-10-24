package coord

import (
	"testing"
	"time"

	"github.com/djylb/holepunch/coord/internal/simclient"
	"github.com/djylb/holepunch/internal/testkit"
	"github.com/djylb/holepunch/protocol"
)

func TestRTTEstimator(t *testing.T) {
	var e rttEstimator
	if _, ok := e.min(); ok || e.jitter() != 0 {
		t.Fatal("empty estimator")
	}
	for _, d := range []time.Duration{0, -time.Millisecond, 5*time.Second + 1} {
		if e.add(d) {
			t.Fatalf("%v accepted", d)
		}
	}
	for _, ms := range []int{50, 40, 90, 60, 45, 70, 80, 85, 95, 100} {
		if !e.add(time.Duration(ms) * time.Millisecond) {
			t.Fatal("valid sample refused")
		}
	}
	// The last 8 are 90..100: the 40 ms sample is gone.
	if m, _ := e.min(); m != 45*time.Millisecond {
		t.Fatalf("min %v", m)
	}
	if j := e.jitter(); j != 20*time.Millisecond { // 85, 95, 100, 80 → 100 − 80
		t.Fatalf("jitter %v", j)
	}
	var big rttEstimator
	big.add(time.Millisecond)
	big.add(time.Second)
	if big.jitter() != jitterCap {
		t.Fatalf("jitter cap %v", big.jitter())
	}
}

func TestAlign(t *testing.T) {
	var a, b rttEstimator
	al := align([2]*rttEstimator{&a, &b}, false)
	if al.rtt != [2]time.Duration{rttDefault, rttDefault} || al.d != rttDefault/2+marginBase {
		t.Fatalf("defaults %+v", al)
	}
	a.add(20 * time.Millisecond)
	al = align([2]*rttEstimator{&a, &b}, false)
	if al.rtt[1] != 20*time.Millisecond {
		t.Fatalf("borrowed rtt %+v", al)
	}
	b.add(200 * time.Millisecond)
	al = align([2]*rttEstimator{&a, &b}, false)
	if al.d != 120*time.Millisecond || al.delay != [2]time.Duration{110 * time.Millisecond, 20 * time.Millisecond} {
		t.Fatalf("aligned %+v", al)
	}
	b.add(4 * time.Second)
	b.add(4900 * time.Millisecond)
	al = align([2]*rttEstimator{&a, &b}, false)
	if al.d > startMax {
		t.Fatalf("D %v", al.d)
	}
	al = align([2]*rttEstimator{&a, &b}, true)
	if al.delay != [2]time.Duration{} {
		t.Fatalf("no-align delays %+v", al.delay)
	}
}

// TestGoAlignmentAsymmetric: the side with the shorter control path waits
// longer, so that both fire D after the go frames left.
func TestGoAlignmentAsymmetric(t *testing.T) {
	r := newRig(t)
	// Pongs would add samples of their own: only the reports' samples count
	// here.
	p := &pair{r: r, s: r.session(SessionOptions{})}
	for i := range 2 {
		p.cl[i] = r.attach(p.s, roleOf(i), simclient.Options{NoPong: true})
		p.starts[i] = expect[protocol.PunchStart](t, p.cl[i])
	}
	r.clk.Advance(10 * time.Millisecond)
	p.report(0)
	testkit.WaitFor(t, "report 0", func() bool { return p.s.Snapshot().Reported[0] })
	r.clk.Advance(190 * time.Millisecond)
	p.report(1)
	var sums [2]*protocol.ProbeSummary
	for i := range 2 {
		sums[i] = expect[protocol.ProbeSummary](t, p.cl[i])
	}
	for i := range 2 {
		send(t, p.cl[i], simclient.Ready(sums[i], roleOf(i), 0))
	}
	var gos [2]*protocol.PunchGo
	for i := range 2 {
		gos[i] = expect[protocol.PunchGo](t, p.cl[i])
	}
	// rtt_I = 10 ms (5 ms from the report's elapsed), rtt_R = 200 ms.
	if gos[0].RTTMs != 5 || gos[1].RTTMs != 195 {
		t.Fatalf("rtt %d %d", gos[0].RTTMs, gos[1].RTTMs)
	}
	oI, oR := 2.5, 97.5
	d := oR + 20
	if got := float64(gos[0].DelayMs); got < d-oI-1 || got > d-oI+1 {
		t.Fatalf("delay I %d", gos[0].DelayMs)
	}
	if got := float64(gos[1].DelayMs); got < d-oR-1 || got > d-oR+1 {
		t.Fatalf("delay R %d", gos[1].DelayMs)
	}
	snap := p.s.Snapshot()
	if snap.RTT[0] != 5*time.Millisecond {
		t.Fatalf("snapshot rtt %v", snap.RTT)
	}
	p.s.Abort(protocol.ReasonCanceled, "")
	r.wait(p.s)
}

// TestPingSchedule: ping#1 goes with punch_start; while one side waits for
// the other's report or ready it gets a ping every 300 ms, at most two per
// phase; all on the session's single timer.
func TestPingSchedule(t *testing.T) {
	r := newRig(t)
	s := r.session(readyGated())
	p := &pair{r: r, s: s}
	p.cl[0] = r.attach(s, protocol.RoleInitiator)
	p.starts[0] = expect[protocol.PunchStart](t, p.cl[0])
	testkit.WaitFor(t, "ping#1", func() bool { return p.cl[0].Pings() == 1 })
	p.report(0)
	testkit.WaitFor(t, "report", func() bool { return s.Snapshot().Reported[0] })
	for want := 2; want <= 4; want++ {
		r.clk.Advance(pingEvery)
		if want <= 3 {
			testkit.WaitFor(t, "ping", func() bool { return p.cl[0].Pings() == want })
		}
	}
	if r.clk.Pending() != 2 { // the housekeeping timer and the session's single timer
		t.Fatalf("%d timers pending", r.clk.Pending())
	}
	if p.cl[0].Pings() != 3 {
		t.Fatalf("%d pings in the report phase", p.cl[0].Pings())
	}
	p.cl[1] = r.attach(s, protocol.RoleResponder)
	p.starts[1] = expect[protocol.PunchStart](t, p.cl[1])
	p.report(1)
	sum := expect[protocol.ProbeSummary](t, p.cl[0])
	expect[protocol.ProbeSummary](t, p.cl[1])
	send(t, p.cl[0], simclient.Ready(sum, protocol.RoleInitiator, 0))
	testkit.WaitFor(t, "ready", func() bool { return s.Snapshot().Ready[0] })
	for range 3 {
		r.clk.Advance(pingEvery)
	}
	testkit.WaitFor(t, "ready-phase pings", func() bool { return p.cl[0].Pings() == 5 })
	if p.cl[1].Pings() != 1 {
		t.Fatalf("responder pings %d", p.cl[1].Pings())
	}
	s.Abort(protocol.ReasonCanceled, "")
	res := r.wait(s)
	if res.Counters.PingsSent != 6 {
		t.Fatalf("pings sent %d", res.Counters.PingsSent)
	}
}

// TestPongSamples: a pong's sample deducts hold_us; unknown and repeated
// pongs are ignored; a skewed client clock is only a warning.
func TestPongSamples(t *testing.T) {
	r := newRig(t)
	s := r.session(SessionOptions{})
	c := r.attach(s, protocol.RoleInitiator, simclient.Options{NoPong: true})
	expect[protocol.PunchStart](t, c)
	testkit.WaitFor(t, "ping#1", func() bool { return c.Pings() == 1 })
	r.clk.Advance(80 * time.Millisecond)
	skewed := r.clk.Now().Add(-time.Hour).UnixMilli()
	send(t, c, &protocol.Pong{Seq: 1, HoldUs: 30000, ClientUnixMs: skewed})
	send(t, c, &protocol.Pong{Seq: 1, HoldUs: 0}) // repeated
	send(t, c, &protocol.Pong{Seq: 5, HoldUs: 0}) // never sent
	testkit.WaitFor(t, "sample", func() bool { return s.Snapshot().RTT[0] != 0 })
	if got := s.Snapshot().RTT[0]; got != 50*time.Millisecond {
		t.Fatalf("rtt %v", got)
	}
	s.Abort(protocol.ReasonCanceled, "")
	res := r.wait(s)
	if !contains(res.Warn, protocol.WarnClockSkew) || res.ClockOffset[0] > -59*time.Minute {
		t.Fatalf("warn %v offset %v", res.Warn, res.ClockOffset)
	}
}
