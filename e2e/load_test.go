//go:build load && unix

package e2e

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"runtime"
	"slices"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"go.uber.org/goleak"

	"github.com/djylb/holepunch/coord"
	"github.com/djylb/holepunch/internal/ablation"
	"github.com/djylb/holepunch/internal/controlwire"
	"github.com/djylb/holepunch/internal/msgframe"
	"github.com/djylb/holepunch/internal/nat"
	"github.com/djylb/holepunch/nattest"
	"github.com/djylb/holepunch/protocol"
)

// Load tests: the coordinator's control plane with 1000 sessions of scripted
// clients (TestLoadControlPlane), and the whole chain with 1000 pairs of real
// clients (TestLoadClients). Run with -tags load, on Unix (getrusage);
// HOLEPUNCH_E2E_LOAD_N changes the number of sessions (pairs).

const envLoadN = "HOLEPUNCH_E2E_LOAD_N"

// loadN is the number of sessions of a load test.
func loadN(t *testing.T) int {
	v, err := envCount(envLoadN)
	if err != nil {
		t.Fatal(err)
	}
	if v > 0 {
		return v
	}
	return 1000
}

// usage is the process's resource use.
type usage struct {
	cpu    time.Duration // user + system
	maxRSS int64         // bytes
}

// processUsage reads getrusage(RUSAGE_SELF).
func processUsage() usage {
	var ru syscall.Rusage
	if err := syscall.Getrusage(syscall.RUSAGE_SELF, &ru); err != nil {
		return usage{}
	}
	rss := int64(ru.Maxrss)
	if runtime.GOOS == "linux" {
		rss *= 1024 // KiB on Linux, bytes on darwin
	}
	return usage{cpu: time.Duration(ru.Utime.Nano() + ru.Stime.Nano()), maxRSS: rss}
}

// sampler records the peaks of goroutines and heap while a load test runs.
type sampler struct {
	stop       chan struct{}
	done       chan struct{}
	once       sync.Once
	goroutines atomic.Int64
	heapInuse  atomic.Uint64
}

// samplePeriod is how often the sampler looks.
const samplePeriod = 50 * time.Millisecond

func startSampler() *sampler {
	s := &sampler{stop: make(chan struct{}), done: make(chan struct{})}
	go func() {
		defer close(s.done)
		tick := time.NewTicker(samplePeriod)
		defer tick.Stop()
		var ms runtime.MemStats
		for {
			if g := int64(runtime.NumGoroutine()); g > s.goroutines.Load() {
				s.goroutines.Store(g)
			}
			runtime.ReadMemStats(&ms)
			if ms.HeapInuse > s.heapInuse.Load() {
				s.heapInuse.Store(ms.HeapInuse)
			}
			select {
			case <-s.stop:
				return
			case <-tick.C:
			}
		}
	}()
	return s
}

// end stops the sampler and waits for it; it is idempotent, so that a test
// may also defer it.
func (s *sampler) end() {
	s.once.Do(func() { close(s.stop) })
	<-s.done
}

// heapInuse returns the live heap after a collection.
func heapInuse() uint64 {
	runtime.GC()
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	return ms.HeapInuse
}

// scripted is a client that speaks the control protocol by script, for the
// control-plane load:
// it answers pings by itself (in the controlwire Intercept, as the runtime
// does) and plays report, ready, round_result{confirmed} and punch_result.
type scripted struct {
	role  protocol.Role
	conn  *controlwire.Conn
	pub   netip.AddrPort
	local netip.AddrPort
}

func newScripted(nc net.Conn, role protocol.Role, pub, local netip.AddrPort) (*scripted, error) {
	s := &scripted{role: role, pub: pub, local: local}
	cw, err := controlwire.NewConn(nc, controlwire.ConnOptions{Side: controlwire.SideClient, Intercept: s.intercept})
	if err != nil {
		return nil, err
	}
	s.conn = cw
	return s, nil
}

func (s *scripted) intercept(cw *controlwire.Conn, f controlwire.Frame) bool {
	if f.Type != controlwire.TypePing {
		return false
	}
	p, err := msgframe.Unmarshal[protocol.Ping](f)
	if err != nil {
		return true
	}
	at := f.At
	_ = cw.SendFunc(controlwire.TypePong, func(now time.Time) ([]byte, error) {
		fr, err := msgframe.Encode(protocol.PongFor(p, at, now))
		return fr.Payload, err
	})
	return true
}

// next reads the next frame of a type, skipping assists and others.
func (s *scripted) next(ctx context.Context, typ controlwire.Type) (controlwire.Frame, error) {
	for {
		f, err := s.conn.ReadFrame(ctx)
		if err != nil {
			return f, err
		}
		if f.Type == typ {
			return f, nil
		}
		if f.Type == controlwire.TypeAbort {
			return f, errors.New("e2e: scripted client aborted")
		}
	}
}

func (s *scripted) send(ctx context.Context, m protocol.Message) error {
	f, err := msgframe.Encode(m)
	if err != nil {
		return err
	}
	return s.conn.WriteFrame(ctx, f)
}

// run plays one session; park holds the client in summarized (before
// ready) until it is closed.
func (s *scripted) run(ctx context.Context, peer netip.AddrPort, park <-chan struct{}) error {
	defer func() { _ = s.conn.Close() }()
	f, err := s.next(ctx, controlwire.TypePunchStart)
	if err != nil {
		return err
	}
	start, err := msgframe.Unmarshal[protocol.PunchStart](f)
	if err != nil {
		return err
	}
	tr := protocol.Traits{Mapping: protocol.MapEIM, MappingConf: protocol.ConfHigh, Filtering: protocol.FiltPDF,
		FilteringConf: protocol.ConfHigh, PortAlloc: protocol.AllocPreserving, PortAllocConf: protocol.ConfHigh,
		PublicIP: s.pub.Addr(), Observed: s.pub, Samples: 3}
	rep := protocol.ProbeReport{
		SessionID: start.SessionID, Role: s.role,
		Control:   protocol.ControlSpec{Version: controlwire.Version, Features: protocol.AcceptFeatures(start.Control.Features, protocol.SupportedFeatures())},
		Caps:      protocol.ClientCaps{Impl: "e2e-load", MaxSockets: 8, Families: []protocol.FamilyCaps{{Family: protocol.FamilyUDP4, LowTTL: true}}},
		ElapsedMs: 5, Transport: protocol.Transport{Mode: "quic"},
		Families: []protocol.FamilyReport{{Family: protocol.FamilyUDP4, Traits: tr, LocalAddrs: []netip.Addr{s.local.Addr()},
			Sockets: []protocol.SocketReport{{ID: nat.SocketID(protocol.FamilyUDP4, nat.IndexPrimary), Kind: protocol.SocketPrimary, Local: s.local,
				Rows: []protocol.RowReport{{Observer: 0, Observed: s.pub, FirstSeq: 1, RTTMs: 10}}}}}},
	}
	if err := s.send(ctx, &rep); err != nil {
		return err
	}
	if f, err = s.next(ctx, controlwire.TypeProbeSummary); err != nil {
		return err
	}
	sum, err := msgframe.Unmarshal[protocol.ProbeSummary](f)
	if err != nil {
		return err
	}
	select {
	case <-park:
	case <-ctx.Done():
		return ctx.Err()
	}
	ready := protocol.PunchReady{SessionID: sum.SessionID, Role: s.role, ElapsedMs: 1}
	for _, side := range sum.Plan.Round1.Sides {
		ready.Families = append(ready.Families, protocol.FamilyReady{Family: side.Family, Sockets: side.Sockets})
	}
	if err := s.send(ctx, &ready); err != nil {
		return err
	}
	if f, err = s.next(ctx, controlwire.TypePunchGo); err != nil {
		return err
	}
	g, err := msgframe.Unmarshal[protocol.PunchGo](f)
	if err != nil {
		return err
	}
	time.Sleep(time.Duration(g.DelayMs) * time.Millisecond)
	path := &protocol.PathInfo{Family: protocol.FamilyUDP4, Local: s.local, Remote: peer, Round: 1, Epoch: 1, CandKind: protocol.CandDirect, Kind: protocol.PathPublic, RTTMs: 10}
	rr := protocol.RoundResult{SessionID: sum.SessionID, Role: s.role, Round: 1, ElapsedMs: 1, Status: protocol.RoundConfirmed, Path: path,
		Families: []protocol.FamilyOutcome{{Family: protocol.FamilyUDP4, Hit: true, Sent: 4, Recv: 2}}}
	if err := s.send(ctx, &rr); err != nil {
		return err
	}
	done := *path
	done.ConfirmedBy = protocol.ConfirmedByAck
	pr := protocol.PunchResult{SessionID: sum.SessionID, Role: s.role, OK: true, Phase: protocol.PhaseDone, Path: &done}
	if err := s.send(ctx, &pr); err != nil {
		return err
	}
	select {
	case <-s.conn.Done():
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// loadAddr returns the i-th scripted client's public and local endpoints.
func loadAddr(i int) (pub, local netip.AddrPort) {
	pub = netip.AddrPortFrom(netip.AddrFrom4([4]byte{198, 18, byte(i >> 8), byte(i)}), 40000)
	local = netip.AddrPortFrom(netip.AddrFrom4([4]byte{10, 9, byte(i >> 8), byte(i)}), 40000)
	return pub, local
}

// Control-plane load targets.
const (
	ctlLoadStartRate          = 100 // sessions started per second
	ctlLoadGoroutinesPerSess  = 5
	ctlLoadGoroutineSlack     = 16
	ctlLoadDispatchP99        = 5 * time.Millisecond
	ctlLoadNewSessionRate     = 500
	ctlLoadScriptedGoroutines = 3 // per scripted client: controlwire reader and writer, the script
)

// TestLoadControlPlane drives 1000 sessions of scripted clients through the
// coordinator (NoObserver mode, so that no UDP is involved) over 2000 nattest
// pipes, 100 new sessions a second: goroutines per session, resident memory,
// dispatch latency of summary and go, NewSession throughput, zero wakeups
// of idle sessions, and nothing left at the end.
func TestLoadControlPlane(t *testing.T) {
	n := loadN(t)
	net0 := nattest.NewNetwork(nattest.WithEventLog(0))
	defer func() { _ = net0.Close() }()
	co, err := coord.New(coord.Config{NoObserver: true, Timeouts: e2eTimeouts(),
		TTL:    coord.TTLConfig{BindTimeout: 30 * time.Second, ReadyTimeout: 15 * time.Second},
		Limits: coord.Limits{NewSessions: coord.Rate{PerSec: 1000, Burst: 1000}, MaxPending: 4096}})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = co.Close() }()

	// NewSession throughput.
	t0 := time.Now()
	var probe []*coord.Session
	for range n {
		s, err := co.NewSession(coord.SessionOptions{})
		if err != nil {
			t.Fatalf("NewSession: %v", err)
		}
		probe = append(probe, s)
	}
	rate := float64(n) / time.Since(t0).Seconds()
	for _, s := range probe {
		s.Abort(protocol.ReasonCanceled, "")
	}

	runtime.GC()
	g0, heap0, u0 := runtime.NumGoroutine(), heapInuse(), processUsage()
	smp := startSampler()
	defer smp.end()
	park := make(chan struct{})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	type sess struct {
		s    *coord.Session
		taps [2]*tap
	}
	sessions := make([]sess, n)
	var wg sync.WaitGroup
	var failed atomic.Int64
	var firstErr atomic.Value
	tick := time.NewTicker(time.Second / ctlLoadStartRate)
	for i := range n {
		<-tick.C
		s, err := co.NewSession(coord.SessionOptions{})
		if err != nil {
			t.Fatalf("session %d: %v", i, err)
		}
		sessions[i].s = s
		for r := range 2 {
			a, b := net0.Pipe(nattest.PipeConfig{DelayAB: 10 * time.Millisecond, DelayBA: 10 * time.Millisecond})
			tp := newTap(b)
			tp.light = true
			sessions[i].taps[r] = tp
			if err := s.Attach(roles[r], tp, coord.AttachOptions{Security: protocol.ControlSecurityInsecureForTesting}); err != nil {
				t.Fatalf("attach: %v", err)
			}
			pub, local := loadAddr(2*i + r)
			peer, _ := loadAddr(2*i + 1 - r)
			cl, err := newScripted(a, roles[r], pub, local)
			if err != nil {
				t.Fatal(err)
			}
			wg.Add(1)
			go func() {
				defer wg.Done()
				if err := cl.run(ctx, peer, park); err != nil {
					failed.Add(1)
					firstErr.CompareAndSwap(nil, err)
				}
			}()
		}
	}
	tick.Stop()

	// Park: every session in summarized; wait for the pings of the phase,
	// then count frames over an idle second.
	waitSummarized := time.Now().Add(30 * time.Second)
	for time.Now().Before(waitSummarized) {
		parked := 0
		for _, s := range sessions {
			if s.s.Snapshot().State == coord.StateSummarized {
				parked++
			}
		}
		if parked == n {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	time.Sleep(2 * time.Second)
	runtime.GC()
	gPark, heapPark := runtime.NumGoroutine(), heapInuse()
	var f0 int64
	for _, s := range sessions {
		f0 += s.taps[0].frames.Load() + s.taps[1].frames.Load()
	}
	time.Sleep(time.Second)
	var f1 int64
	for _, s := range sessions {
		f1 += s.taps[0].frames.Load() + s.taps[1].frames.Load()
	}
	close(park)
	wg.Wait()
	for i, s := range sessions {
		select {
		case <-s.s.Done():
		case <-ctx.Done():
			t.Fatalf("session %d did not end: %v", i, ctx.Err())
		}
	}
	smp.end()
	u1 := processUsage()

	// Dispatch latency: the go of a round goes out with the second ready.
	var lat []float64
	for _, s := range sessions {
		lastReady, goAt := readyToGo(s.taps)
		if !lastReady.IsZero() && !goAt.IsZero() {
			lat = append(lat, ms(goAt.Sub(lastReady)))
		}
	}
	q := quant(lat)
	serverG := float64(gPark-g0-ctlLoadScriptedGoroutines*2*n) / float64(n)
	perSession := float64(int64(heapPark)-int64(heap0)) / float64(n)
	st := co.Stats()
	t.Logf("control plane: %d sessions, NewSession %.0f/s, server goroutines %.2f/session (park), heap %.1f KiB/session (park, clients and pipes included), "+
		"dispatch p50 %.2f ms p99 %.2f ms (n=%d), idle frames %d in 1 s, CPU %v, max RSS %.1f MiB, peak goroutines %d, peak heap %.1f MiB, ok %d, failed %d (%v)",
		n, rate, serverG, perSession/1024, q.P50, pctl(lat, 0.99), q.N, f1-f0, u1.cpu-u0.cpu, float64(u1.maxRSS)/(1<<20),
		smp.goroutines.Load(), float64(smp.heapInuse.Load())/(1<<20), st.ByOutcome[0], failed.Load(), firstErr.Load())
	if failed.Load() != 0 {
		t.Errorf("%d scripted clients failed: %v", failed.Load(), firstErr.Load())
	}
	if serverG > ctlLoadGoroutinesPerSess+float64(ctlLoadGoroutineSlack)/float64(n) {
		t.Errorf("%.2f server goroutines per session, bound %d", serverG, ctlLoadGoroutinesPerSess)
	}
	if p := pctl(lat, 0.99); p > ms(scaled(ctlLoadDispatchP99)) {
		t.Errorf("go dispatch p99 %.2f ms, bound %v", p, scaled(ctlLoadDispatchP99))
	}
	if rate < ctlLoadNewSessionRate {
		t.Errorf("NewSession %.0f/s, want ≥ %d/s", rate, ctlLoadNewSessionRate)
	}
	if f1 != f0 {
		t.Errorf("%d frames on idle links within a second", f1-f0)
	}
	if co.Len() != 0 || st.ActiveByKey != 0 {
		t.Errorf("coordinator holds %d sessions, %d keys", co.Len(), st.ActiveByKey)
	}
	if err := co.Close(); err != nil {
		t.Errorf("coordinator close: %v", err)
	}
	if err := net0.Close(); err != nil {
		t.Errorf("network close: %v", err)
	}
	goleak.VerifyNone(t)
}

// readyToGo returns when the coordinator read the second punch_ready and
// when it wrote the first go, from a session's two taps.
func readyToGo(taps [2]*tap) (lastReady, goAt time.Time) {
	for _, tp := range taps {
		for _, ev := range tp.log() {
			switch {
			case ev.Dir == toServer && ev.Type == controlwire.TypePunchReady && ev.At.After(lastReady):
				lastReady = ev.At
			case ev.Dir == toClient && ev.Type == controlwire.TypePunchGo && (goAt.IsZero() || ev.At.Before(goAt)):
				goAt = ev.At
			}
		}
	}
	return lastReady, goAt
}

// pctl returns the p-quantile (nearest rank) of xs, or -1.
func pctl(xs []float64, p float64) float64 {
	if len(xs) == 0 {
		return -1
	}
	s := slices.Clone(xs)
	slices.Sort(s)
	i := int(float64(len(s))*p+0.999999) - 1
	return s[max(min(i, len(s)-1), 0)]
}

// clientLoadMix is the mix of the client load: 800 PRC×PRC, 150 FC×SYMSEQ,
// 50 PRC×SYMSEQ out of 1000.
var clientLoadMix = []struct {
	cell  string
	share int // per mille
}{{"v4/PRC-PRC", 800}, {"v4/FC-SYMSEQ", 150}, {"v4/PRC-SYMSEQ", 50}}

// Client load targets.
const (
	clientLoadBaselineRuns   = 20
	clientLoadSuccessSlack   = 0.02
	clientLoadHeapPerSession = 1 << 20
)

// TestLoadClients runs 1000 pairs of real clients through one coordinator and
// one natprobe at once, after a single-pair baseline of each
// cell, and records the success rates, CPU time, peak RSS, goroutines and
// heap per session; everything must be released at the end.
func TestLoadClients(t *testing.T) {
	n := loadN(t)
	byName := map[string]*cell{}
	for _, c := range cells() {
		byName[c.name] = c
	}
	// Baseline: each cell alone.
	base := map[string]float64{}
	for _, m := range clientLoadMix {
		ok := 0
		for i := range clientLoadBaselineRuns {
			cr, _ := runOnce(t, byName[m.cell], cellSeed("load/"+m.cell, i), ablation.Set{}, false)
			if cr.m.OK {
				ok++
			}
		}
		base[m.cell] = float64(ok) / clientLoadBaselineRuns
	}

	w := newWorld(t, worldConfig{seed: suite().seed, eventLog: -1,
		limits: coord.Limits{NewSessions: coord.Rate{PerSec: -1}, MaxPending: 4096, MaxSessions: 4096}})
	defer func() { _ = w.close() }() // a failed test's; the close below reports its errors
	var runs []*run
	var kinds []string
	for _, m := range clientLoadMix {
		c := byName[m.cell]
		for range n * m.share / 1000 {
			sides := c.build(w)
			r, err := newRun(w, sides, sessionSpec{lightTaps: true})
			if err != nil {
				t.Fatalf("session: %v", err)
			}
			runs = append(runs, r)
			kinds = append(kinds, m.cell)
		}
	}
	runtime.GC()
	g0, heap0, u0 := runtime.NumGoroutine(), heapInuse(), processUsage()
	smp := startSampler()
	defer smp.end()
	start := time.Now()
	var wg sync.WaitGroup
	for _, r := range runs {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r.execute()
		}()
	}
	wg.Wait()
	elapsed := time.Since(start)
	smp.end()
	u1 := processUsage()
	ok := map[string]int{}
	total := map[string]int{}
	for i, r := range runs {
		total[kinds[i]]++
		if r.out[0].ok() && r.out[1].ok() {
			ok[kinds[i]]++
		}
	}
	for _, r := range runs {
		if err := r.closeSessions(); err != nil {
			t.Error(err)
		}
	}
	open := 0
	for _, r := range runs {
		open += r.sides[0].host.OpenSockets() + r.sides[1].host.OpenSockets()
	}
	peakHeap := smp.heapInuse.Load()
	perClient := float64(int64(peakHeap)-int64(heap0)) / float64(2*len(runs))
	t.Logf("clients: %d pairs in %v, CPU %v (%.1f cores), max RSS %.1f MiB, peak goroutines %d (baseline %d), peak heap %.1f MiB, %.1f KiB per client session",
		len(runs), elapsed.Round(time.Millisecond), u1.cpu-u0.cpu, (u1.cpu-u0.cpu).Seconds()/elapsed.Seconds(),
		float64(u1.maxRSS)/(1<<20), smp.goroutines.Load(), g0, float64(peakHeap)/(1<<20), perClient/1024)
	for _, m := range clientLoadMix {
		rate := float64(ok[m.cell]) / float64(max(total[m.cell], 1))
		t.Logf("%s: %d/%d (%.1f%%), single-pair baseline %.0f%%", m.cell, ok[m.cell], total[m.cell], 100*rate, 100*base[m.cell])
		if rate < base[m.cell]-clientLoadSuccessSlack {
			t.Errorf("%s: success %.1f%% under load, baseline %.0f%% − 2 pts", m.cell, 100*rate, 100*base[m.cell])
		}
	}
	if perClient > clientLoadHeapPerSession {
		t.Errorf("%.0f KiB per client session, bound %d KiB", perClient/1024, clientLoadHeapPerSession>>10)
	}
	if open != 0 {
		t.Errorf("%d sockets open after every session closed", open)
	}
	if err := w.close(); err != nil {
		t.Error(err)
	}
	goleak.VerifyNone(t)
}
