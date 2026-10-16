package candidate

import (
	"fmt"
	"math/rand/v2"
	"net/netip"
	"slices"
	"testing"
	"time"

	"github.com/djylb/holepunch/protocol"
)

// Regression tests for defects fixed in the candidate table and the
// nomination state machine.

// readying drives an initiator with one responsive pair to PhaseReadying and
// returns the instant it confirmed.
func readying(t *testing.T, m *Manager, base time.Time, loc, rem netip.AddrPort) time.Time {
	t.Helper()
	m.Success(base, loc, rem, protocol.FamilyUDP4, 40*time.Millisecond)
	for ms := 0; ms <= 400; ms++ {
		now := base.Add(time.Duration(ms) * time.Millisecond)
		for _, a := range m.Tick(now) {
			if a.Kind == SendNominate && m.Phase() == PhaseNominating {
				m.RecvAccept(now, a.Epoch, rem, 0)
				return now
			}
		}
	}
	t.Fatalf("phase %v, want readying", m.Phase())
	return time.Time{}
}

// An RTT above four rto no longer livelocks. Each epoch roll of
// a pair doubles its rto (up to 1200 ms), so a later campaign outlasts the
// round trip and its accept arrives in time; both sides hand over on the same
// pair and epoch.
func TestHighRTTConverges(t *testing.T) {
	cases := []struct{ sample, actual time.Duration }{
		{590 * time.Millisecond, 590 * time.Millisecond},
		{610 * time.Millisecond, 610 * time.Millisecond},
		{700 * time.Millisecond, 700 * time.Millisecond},
		{50 * time.Millisecond, 410 * time.Millisecond}, // stale sample, queueing during a burst
		{1200 * time.Millisecond, 1200 * time.Millisecond},
	}
	for _, c := range cases {
		for _, paths := range [][]simPath{twoPaths()[:1], twoPaths()} {
			for i := range paths {
				paths[i].rttSample = c.sample
			}
			cfg := simCfg{oneWay: c.actual / 2, tickStep: time.Millisecond, horizon: 30 * time.Second, paths: paths}
			r := runSim(cfg, rand.New(rand.NewPCG(1, 1)))
			if !r.iDone || !r.rDone || r.iPath != r.rPath || r.iEpoch != r.rEpoch {
				t.Fatalf("rtt %v (sample %v, %d paths): I done %v R done %v, paths %d/%d, epochs %d/%d\n%v",
					c.actual, c.sample, len(paths), r.iDone, r.rDone, r.iPath, r.rPath, r.iEpoch, r.rEpoch, tail(r.log, 20))
			}
		}
	}
}

// The backoff is per pair and capped.
func TestRTOBackoffPerPair(t *testing.T) {
	m := NewManager(Config{Role: protocol.RoleInitiator})
	m.cur = &Candidate{MinRTT: 100 * time.Millisecond}
	for k, ms := range []int{150, 300, 600, 1200, 1200, 1200} {
		m.cur.NomFailures = k
		if got, want := m.rto(), time.Duration(ms)*time.Millisecond; got != want {
			t.Fatalf("rto after %d rolls = %v, want %v", k, got, want)
		}
	}
	m.cur = &Candidate{MinRTT: 10 * time.Millisecond, NomFailures: 1}
	if got := m.rto(); got != 80*time.Millisecond {
		t.Fatalf("rto of a 10 ms pair after one roll = %v, want 80 ms", got)
	}
}

// On a LAN the initiator's first upper-layer datagram must not
// reach the responder before it handed over. The responder hands over by
// ready at the end of its burst, never after reading the upper layer.
func TestLANUpperLayerNotSwallowed(t *testing.T) {
	for _, owd := range []time.Duration{0, time.Millisecond, 5 * time.Millisecond, 14 * time.Millisecond} {
		paths := []simPath{{iLoc: ap("192.168.1.2:5000"), rAddr: ap("192.168.1.3:6000"), rLoc: ap("192.168.1.3:6000"),
			iAddr: ap("192.168.1.2:5000"), rttSample: max(2*owd, time.Millisecond), kindI: KindLAN}}
		cfg := simCfg{oneWay: owd, tickStep: time.Millisecond, horizon: 2 * time.Second, paths: paths, upperPTO: 200 * time.Millisecond}
		r := runSim(cfg, rand.New(rand.NewPCG(1, 1)))
		if !r.iDone || !r.rDone || r.upperBeforeR != 0 || r.rBy != protocol.ConfirmedByReady || r.iBy != protocol.ConfirmedByAck {
			t.Fatalf("owd %v: I %v by %s at %v, R %v by %s at %v, upper datagrams read by R's library %d\n%v",
				owd, r.iDone, r.iBy, r.iDoneAt, r.rDone, r.rBy, r.rDoneAt, r.upperBeforeR, r.log)
		}
	}
}

// The initiator hands over 30 ms after its first ack once it has
// three, 45 ms after the first at the latest, and at once on an upper-layer
// datagram from the winning remote.
func TestInitiatorAckHandoverTiming(t *testing.T) {
	base := time.Unix(0, 0)
	loc, rem := ap("192.0.2.1:5000"), ap("203.0.113.9:40000")
	run := func(acks []time.Duration) (time.Duration, protocol.HandoverEvidence) {
		m := NewManager(Config{Role: protocol.RoleInitiator})
		c := readying(t, m, base, loc, rem)
		next := 0
		for ms := time.Duration(0); ms <= 100*time.Millisecond; ms += time.Millisecond {
			now := c.Add(ms)
			var acts []Action
			for next < len(acks) && acks[next] == ms {
				acts = append(acts, m.RecvHandoverAck(now, m.Epoch(), rem)...)
				next++
			}
			acts = append(acts, m.Tick(now)...)
			for _, a := range acts {
				if a.Kind == HandOver {
					return ms, a.ConfirmedBy
				}
			}
		}
		return -1, ""
	}
	for _, c := range []struct {
		acks []int // ms after Confirm
		want int
	}{
		{[]int{5, 15, 20}, 35},     // three acks: first + 30
		{[]int{5, 20, 50}, 50},     // the third after first + 45: first + 45
		{[]int{5, 35, 40}, 40},     // the third between first + 30 and first + 45: at the third
		{[]int{5}, 50},             // only one: first + 45
		{[]int{5, 15, 20, 21}, 35}, // a fourth changes nothing
	} {
		acks := make([]time.Duration, len(c.acks))
		for i, a := range c.acks {
			acks[i] = time.Duration(a) * time.Millisecond
		}
		at, by := run(acks)
		if at != time.Duration(c.want)*time.Millisecond || by != protocol.ConfirmedByAck {
			t.Fatalf("acks at %v ms: handover at %v by %q, want %d ms", c.acks, at, by, c.want)
		}
	}
	m := NewManager(Config{Role: protocol.RoleInitiator})
	c := readying(t, m, base, loc, rem)
	m.RecvHandoverAck(c.Add(5*time.Millisecond), m.Epoch(), rem)
	if acts := m.RecvUpperLayer(c.Add(6*time.Millisecond), netip.AddrPort{}, rem); count(acts, HandOver) != 1 || acts[0].ConfirmedBy != protocol.ConfirmedByUpperLayer {
		t.Fatalf("upper-layer datagram did not hand over at once: %+v", acts)
	}
}

// A responder in its ack burst that reads an upper-layer datagram hands
// over at once instead of reading more.
func TestResponderUpperLayerDuringBurst(t *testing.T) {
	r := NewManager(Config{Role: protocol.RoleResponder})
	base := time.Unix(0, 0)
	loc, rem := ap("198.51.100.5:6000"), ap("203.0.113.1:50000")
	r.Success(base, loc, rem, protocol.FamilyUDP4, 40*time.Millisecond)
	r.RecvNominate(base, 1, loc, rem, protocol.FamilyUDP4)
	r.RecvReady(base.Add(20*time.Millisecond), 1, rem, 0)
	acts := r.RecvUpperLayer(base.Add(25*time.Millisecond), netip.AddrPort{}, rem)
	if count(acts, HandOver) != 1 || acts[0].ConfirmedBy != protocol.ConfirmedByUpperLayer || r.Phase() != PhaseDone {
		t.Fatalf("burst + upper layer: %+v, phase %v", acts, r.Phase())
	}
}

// NextDeadline exposes the next timer, so a caller that sleeps
// on one timer and never polls keeps every instant exact: the ×2 first burst
// 10 ms apart, the rto resend, the 15/30 ms acks.
func TestNextDeadlineDrivesExactly(t *testing.T) {
	base := time.Unix(0, 0)
	m := NewManager(Config{Role: protocol.RoleInitiator})
	if _, ok := m.NextDeadline(); ok {
		t.Fatal("a deadline before any success")
	}
	loc, rem := ap("192.0.2.1:5000"), ap("203.0.113.9:40000")
	m.Success(base, loc, rem, protocol.FamilyUDP4, 40*time.Millisecond)
	var noms []time.Duration
	for range 4 {
		at, ok := m.NextDeadline()
		if !ok {
			t.Fatal("no deadline while nominating")
		}
		for _, a := range m.Tick(at) {
			if a.Kind == SendNominate {
				noms = append(noms, at.Sub(base))
			}
		}
	}
	// collect 60 ms (clamp(250)), ×2 at 60/70, rto 80 → 140, 220
	want := []time.Duration{60 * time.Millisecond, 70 * time.Millisecond, 140 * time.Millisecond, 220 * time.Millisecond}
	if !slices.Equal(noms, want) {
		t.Fatalf("nominates at %v, want %v", noms, want)
	}

	r := NewManager(Config{Role: protocol.RoleResponder})
	rl, ra := ap("198.51.100.5:6000"), ap("203.0.113.1:50000")
	r.Success(base, rl, ra, protocol.FamilyUDP4, 40*time.Millisecond)
	r.RecvNominate(base, 1, rl, ra, protocol.FamilyUDP4)
	conf := base.Add(20 * time.Millisecond)
	r.RecvReady(conf, 1, ra, 0)
	var acks []time.Duration
	for {
		at, ok := r.NextDeadline()
		if !ok {
			break
		}
		for _, a := range r.Tick(at) {
			if a.Kind == SendAck {
				acks = append(acks, at.Sub(conf))
			}
		}
	}
	if len(acks) != 2 || acks[0] != 15*time.Millisecond || acks[1] != 30*time.Millisecond || r.Phase() != PhaseDone {
		t.Fatalf("acks after confirm at %v, phase %v", acks, r.Phase())
	}
	if _, ok := r.NextDeadline(); ok {
		t.Fatal("a deadline after the handover")
	}
}

// A read error on the winning socket disables the quiet
// evidence; the initiator fails at handover_timeout instead, and the pair is
// closed for good.
func TestReadFailedDisablesQuiet(t *testing.T) {
	base := time.Unix(0, 0)
	loc, rem := ap("192.0.2.1:5000"), ap("203.0.113.9:40000")
	m := NewManager(Config{Role: protocol.RoleInitiator, HandoverTimeout: time.Second})
	c := readying(t, m, base, loc, rem)
	if acts := m.ReadFailed(c.Add(50*time.Millisecond), loc); len(acts) != 0 {
		t.Fatalf("ReadFailed acted: %+v", acts)
	}
	var got []Action
	for {
		at, ok := m.NextDeadline()
		if !ok {
			break
		}
		got = append(got, m.Tick(at)...)
	}
	last := got[len(got)-1]
	if count(got, HandOver) != 0 || last.Kind != Fail || last.Reason != protocol.ReasonHandoverTimeout || m.Phase() != PhaseFailed {
		t.Fatalf("after a winner read error: %+v, phase %v", got, m.Phase())
	}
	if w, _ := m.Winner(); w.State != StateClosed {
		t.Fatalf("winner state %v, want closed", w.State)
	}
	// Without the read error the same silence hands over by quiet.
	m = NewManager(Config{Role: protocol.RoleInitiator, HandoverTimeout: time.Second})
	readying(t, m, base, loc, rem)
	got = nil
	for {
		at, ok := m.NextDeadline()
		if !ok {
			break
		}
		got = append(got, m.Tick(at)...)
	}
	if last := got[len(got)-1]; last.Kind != HandOver || last.ConfirmedBy != protocol.ConfirmedByQuiet {
		t.Fatalf("silence without a read error: %+v", got)
	}
}

// Before Confirm, the initiator abandons a nominated pair whose socket
// failed and nominates another one at a new epoch; the closed pair is never
// nominated again.
func TestReadFailedRenominates(t *testing.T) {
	base := time.Unix(0, 0)
	m := NewManager(Config{Role: protocol.RoleInitiator})
	l1, l2, rem := ap("192.0.2.1:5000"), ap("192.0.2.1:5001"), ap("203.0.113.9:40000")
	m.Observe(base, l1, rem, protocol.FamilyUDP4, KindObserved)
	m.Success(base, l1, rem, protocol.FamilyUDP4, 40*time.Millisecond)
	m.Success(base, l2, rem, protocol.FamilyUDP4, 40*time.Millisecond)
	at, _ := m.NextDeadline()
	if acts := m.Tick(at); count(acts, SendNominate) != 1 || acts[0].Local != l1 {
		t.Fatalf("first nomination %+v", acts)
	}
	acts := m.ReadFailed(at.Add(5*time.Millisecond), l1)
	if count(acts, SendNominate) != 1 || acts[0].Local != l2 || acts[0].Epoch != 2 {
		t.Fatalf("after the nominated socket failed: %+v", acts)
	}
	if c := m.Table().get(l1, rem); c.State != StateClosed {
		t.Fatalf("closed pair state %v", c.State)
	}
	// l2 fails too: nothing left, back to punching; a closed pair never returns.
	if acts := m.ReadFailed(at.Add(6*time.Millisecond), l2); len(acts) != 0 || m.Phase() != PhasePunching {
		t.Fatalf("no pair left: %+v, phase %v", acts, m.Phase())
	}
	m.Success(at.Add(7*time.Millisecond), l1, rem, protocol.FamilyUDP4, 0)
	if b := m.Table().Best(at.Add(time.Second)); b != nil {
		t.Fatalf("a closed pair is nominated again: %v", b.Local)
	}
}

// The table is bounded; Best does not allocate; the nominated pair is
// never evicted.
func TestTableBounded(t *testing.T) {
	m := NewManager(Config{Role: protocol.RoleInitiator})
	base := time.Unix(0, 0)
	loc := ap("192.0.2.1:5000")
	first := netip.AddrPortFrom(netip.AddrFrom4([4]byte{203, 0, 0, 1}), 40000)
	m.Observe(base, loc, first, protocol.FamilyUDP4, KindObserved)
	m.Success(base, loc, first, protocol.FamilyUDP4, 0)
	at, _ := m.NextDeadline()
	if acts := m.Tick(at); count(acts, SendNominate) != 1 {
		t.Fatalf("not nominating: %+v", acts)
	}
	for i := 2; i < 20000; i++ {
		ip := netip.AddrFrom4([4]byte{203, byte(i >> 16), byte(i >> 8), byte(i)})
		m.Success(at.Add(time.Duration(i)*time.Microsecond), loc, netip.AddrPortFrom(ip, 40000), protocol.FamilyUDP4, 0)
	}
	if n := m.Table().Len(); n > maxCandidates {
		t.Fatalf("table holds %d > %d", n, maxCandidates)
	}
	if c := m.Table().get(loc, first); c == nil || c.State != StateNominated {
		t.Fatal("the nominated pair was evicted")
	}
	if a := testing.AllocsPerRun(10, func() { m.Table().Best(at) }); a != 0 {
		t.Fatalf("Best allocates %v times", a)
	}
	// non-responsive candidates go before responsive ones
	tab := newTable()
	for i := range maxCandidates {
		tab.Success(base, loc, netip.AddrPortFrom(netip.AddrFrom4([4]byte{198, 51, byte(i >> 8), byte(i)}), 1), protocol.FamilyUDP4, 0)
	}
	idle := ap("192.0.2.99:1")
	tab.Observe(base.Add(time.Second), loc, idle, protocol.FamilyUDP4, KindPredicted)
	tab.Observe(base.Add(2*time.Second), loc, ap("192.0.2.98:1"), protocol.FamilyUDP4, KindPredicted)
	if tab.get(loc, idle) != nil || tab.Len() != maxCandidates {
		t.Fatalf("the idle candidate survived (len %d)", tab.Len())
	}
}

// An extra ready during the burst is answered at once, not appended
// after the +30 ms ack.
func TestExtraAckImmediate(t *testing.T) {
	r := NewManager(Config{Role: protocol.RoleResponder})
	base := time.Unix(0, 0)
	loc, rem := ap("198.51.100.5:6000"), ap("203.0.113.1:50000")
	r.Success(base, loc, rem, protocol.FamilyUDP4, 40*time.Millisecond)
	r.RecvNominate(base, 1, loc, rem, protocol.FamilyUDP4)
	conf := base.Add(20 * time.Millisecond)
	if acts := r.RecvReady(conf, 1, rem, 0); count(acts, SendAck) != 1 {
		t.Fatalf("confirm: %+v", acts)
	}
	for i, d := range []time.Duration{2 * time.Millisecond, 3 * time.Millisecond, 4 * time.Millisecond} {
		acts := r.RecvReady(conf.Add(d), 1, rem, 0)
		if want := min(1, 2-i); count(acts, SendAck) != max(want, 0) {
			t.Fatalf("extra ready %d: %+v", i+1, acts)
		}
	}
	var times []time.Duration
	for ms := time.Duration(0); ms <= 60*time.Millisecond; ms += time.Millisecond {
		for _, a := range r.Tick(conf.Add(ms)) {
			if a.Kind == SendAck {
				times = append(times, ms)
			}
		}
	}
	if len(times) != 2 || times[0] != 15*time.Millisecond || times[1] != 30*time.Millisecond {
		t.Fatalf("scheduled acks at %v", times)
	}
}

// Every message is checked against the epoch it answers.
func TestStaleEpochIgnored(t *testing.T) {
	base := time.Unix(0, 0)
	loc, rem := ap("192.0.2.1:5000"), ap("203.0.113.9:40000")
	m := NewManager(Config{Role: protocol.RoleInitiator})
	c := readying(t, m, base, loc, rem)
	if acts := m.RecvAccept(c.Add(400*time.Millisecond), m.Epoch()+7, rem, 0); len(acts) != 0 {
		t.Fatalf("a stale accept re-sent ready: %+v", acts)
	}
	if acts := m.RecvHandoverAck(c.Add(401*time.Millisecond), m.Epoch()+7, rem); len(acts) != 0 || m.acks != 0 {
		t.Fatalf("a handover_ack of another epoch counted: %+v", acts)
	}
	r := NewManager(Config{Role: protocol.RoleResponder})
	rl, ra := ap("198.51.100.5:6000"), ap("203.0.113.1:50000")
	r.Success(base, rl, ra, protocol.FamilyUDP4, 0)
	r.RecvNominate(base, 3, rl, ra, protocol.FamilyUDP4)
	if acts := r.RecvReady(base.Add(5*time.Millisecond), 2, ra, 0); len(acts) != 0 {
		t.Fatalf("a ready of another epoch confirmed: %+v", acts)
	}
	r.RecvReady(base.Add(6*time.Millisecond), 3, ra, 0)
	if acts := r.RecvReady(base.Add(7*time.Millisecond), 2, ra, 0); len(acts) != 0 {
		t.Fatalf("a stale ready in the burst got an extra ack: %+v", acts)
	}
}

// The responder adopts only an observed pair: one a peer
// packet arrived on.
func TestResponderAdoptsObservedPairOnly(t *testing.T) {
	r := NewManager(Config{Role: protocol.RoleResponder})
	base := time.Unix(0, 0)
	loc, rem := ap("198.51.100.5:6000"), ap("203.0.113.77:1234")
	if acts := r.RecvNominate(base, 1, loc, rem, protocol.FamilyUDP4); len(acts) != 0 || r.Phase() != PhasePunching {
		t.Fatalf("adopted an unobserved pair: %+v", acts)
	}
	r.Observe(base, loc, rem, protocol.FamilyUDP4, KindPredicted) // planned, never answered
	if acts := r.RecvNominate(base, 1, loc, rem, protocol.FamilyUDP4); len(acts) != 0 {
		t.Fatalf("adopted a planned pair no packet arrived on: %+v", acts)
	}
	r.Success(base.Add(time.Millisecond), loc, rem, protocol.FamilyUDP4, 0)
	if acts := r.RecvNominate(base.Add(2*time.Millisecond), 1, loc, rem, protocol.FamilyUDP4); count(acts, SendAccept) != 1 {
		t.Fatalf("an observed pair was not adopted: %+v", acts)
	}
	r.RecvReady(base.Add(3*time.Millisecond), 1, rem, 0)
	if w, ok := r.Winner(); !ok || w.CandKind() != protocol.CandPredicted {
		t.Fatalf("winner %+v", w)
	}
}

// The nominee only changes to a higher tier. Only responsive pairs are
// nominated; their tier scores differ by more than the 32-point hysteresis
// and a tier shares its reason, so the switch rule "score lead > 32 and a
// different reason" is exactly "a higher tier".
func TestNomineeChangesOnlyToHigherTier(t *testing.T) {
	const hysteresis = 32
	kinds := []Kind{KindUnknown, KindBirthday, KindRandom, KindPredicted, KindTargets, KindObserved, KindLAN}
	base := time.Unix(0, 0)
	loc := ap("192.0.2.1:5000")
	for i, a := range kinds {
		for j, b := range kinds {
			tab := newTable()
			ra, rb := ap(fmt.Sprintf("203.0.113.1:%d", 1+i)), ap(fmt.Sprintf("203.0.113.2:%d", 1+j))
			tab.Observe(base, loc, ra, protocol.FamilyUDP4, a)
			tab.Observe(base, loc, rb, protocol.FamilyUDP4, b)
			ca, cb := tab.Success(base, loc, ra, protocol.FamilyUDP4, 0), tab.Success(base, loc, rb, protocol.FamilyUDP4, 0)
			diff := ca.Score() - cb.Score()
			if diff == 0 {
				if a != b || ca.Reason != cb.Reason {
					t.Fatalf("%v and %v share a score", a, b)
				}
				continue
			}
			spec := diff > hysteresis && ca.Reason != cb.Reason
			if betterForNomination(ca, cb) != spec {
				t.Fatalf("%v vs %v: diff %d, replaces %v, the switch rule says %v", a, b, diff, !spec, spec)
			}
		}
	}
}

// An invalid role never acts; out-of-range settings are clamped to
// their ranges.
func TestInvalidRoleAndClamps(t *testing.T) {
	base := time.Unix(0, 0)
	loc, rem := ap("192.0.2.1:5000"), ap("203.0.113.9:40000")
	for _, role := range []protocol.Role{"", protocol.RoleServer, "bogus"} {
		m := NewManager(Config{Role: role})
		m.Success(base, loc, rem, protocol.FamilyUDP4, 0)
		acts := m.Tick(base.Add(time.Second))
		acts = append(acts, m.RecvNominate(base, 1, loc, rem, protocol.FamilyUDP4)...)
		acts = append(acts, m.RecvAccept(base, 0, rem, 0)...)
		acts = append(acts, m.RecvReady(base, 0, rem, 0)...)
		acts = append(acts, m.ReadFailed(base, loc)...)
		if len(acts) != 0 || m.Phase() != PhasePunching || m.Table().Len() != 0 {
			t.Fatalf("role %q acted: %+v, phase %v", role, acts, m.Phase())
		}
		if _, ok := m.NextDeadline(); ok {
			t.Fatalf("role %q armed a timer", role)
		}
	}
	for _, c := range []struct {
		in, want Config
	}{
		{Config{}, Config{HandoverTimeout: 2 * time.Second, EpochCooldown: 500 * time.Millisecond, MaxNominateResends: 3, MaxPaths: 1}},
		{Config{HandoverTimeout: time.Millisecond, EpochCooldown: time.Millisecond, MaxNominateResends: 1, MaxPaths: -3},
			Config{HandoverTimeout: 500 * time.Millisecond, EpochCooldown: 250 * time.Millisecond, MaxNominateResends: 2, MaxPaths: 1}},
		{Config{HandoverTimeout: time.Hour, EpochCooldown: time.Hour, MaxNominateResends: 100, MaxPaths: 100},
			Config{HandoverTimeout: 10 * time.Second, EpochCooldown: 2 * time.Second, MaxNominateResends: 6, MaxPaths: protocol.MaxPaths}},
	} {
		if got := c.in.normalized(); got != c.want {
			t.Fatalf("normalized(%+v) = %+v, want %+v", c.in, got, c.want)
		}
	}
}

// A target of a peer_targets assist reports cand_kind=targets.
func TestCandKindTargets(t *testing.T) {
	c := &Candidate{Kind: KindTargets, Responsive: true}
	if c.CandKind() != protocol.CandTargets {
		t.Fatalf("cand_kind %q", c.CandKind())
	}
	if KindObserved.baseScore() <= KindTargets.baseScore() || KindTargets.baseScore() <= KindPredicted.baseScore() {
		t.Fatal("peer_targets must rank between observed and predicted")
	}
}

// Random event sequences — time going backwards, zero addresses, invalid
// roles, stale and garbage epochs, garbage slots, rooms and PATHS, read
// errors — never panic, never confirm or hand over twice, never send after a
// terminal action, a handover always names the confirmed pair and epoch, and
// the extra paths handed over are within MaxPaths and no duplicate of the
// primary path or of one another.
func TestRandomEventsInvariants(t *testing.T) {
	addrs := []netip.AddrPort{{}, ap("192.0.2.1:1"), ap("192.0.2.1:2"), ap("203.0.113.9:40000"), ap("203.0.113.9:40001"), ap("[2001:db8::1]:5")}
	seeds := uint64(4000)
	if testing.Short() {
		seeds = 500
	}
	for seed := range seeds {
		rng := rand.New(rand.NewPCG(seed, 9))
		role := []protocol.Role{protocol.RoleInitiator, protocol.RoleResponder, "", protocol.RoleServer}[rng.IntN(4)]
		m := NewManager(Config{Role: role, MaxPaths: rng.IntN(protocol.MaxPaths + 2)})
		now := time.Unix(500, 0)
		confirms, handovers, fails := 0, 0, 0
		var confA Action
		check := func(ev string, acts []Action) {
			for _, a := range acts {
				switch a.Kind {
				case Confirm:
					confirms++
					confA = a
				case HandOver:
					handovers++
					if confirms == 0 || a.Local != confA.Local || a.Remote != confA.Remote || a.Epoch != confA.Epoch {
						t.Fatalf("seed %d %s: handover %+v, confirm %+v", seed, ev, a, confA)
					}
					w, _ := m.Winner()
					held := []*Candidate{&w}
					xs := m.Extras()
					for i := range xs {
						if duplicateOfAny(&xs[i], held) {
							t.Fatalf("seed %d %s: duplicate extra paths %v (primary %v)", seed, ev, xs, w)
						}
						held = append(held, &xs[i])
					}
					if len(xs) > m.cfg.MaxPaths-1 {
						t.Fatalf("seed %d %s: %d extra paths, MaxPaths %d", seed, ev, len(xs), m.cfg.MaxPaths)
					}
				case Fail:
					fails++
				default:
					if handovers > 0 || fails > 0 {
						t.Fatalf("seed %d %s: send %v after a terminal action", seed, ev, a.Kind)
					}
				}
			}
			if confirms > 1 || handovers > 1 || fails > 1 || (handovers > 0 && fails > 0) {
				t.Fatalf("seed %d %s: confirms=%d handovers=%d fails=%d", seed, ev, confirms, handovers, fails)
			}
		}
		for step := range 300 {
			switch rng.IntN(20) {
			case 0:
				now = now.Add(-time.Duration(rng.IntN(200)) * time.Millisecond)
			case 1:
				now = now.Add(time.Duration(rng.IntN(5000)) * time.Millisecond)
			default:
				now = now.Add(time.Duration(rng.IntN(20)) * time.Millisecond)
			}
			l, r := addrs[rng.IntN(len(addrs))], addrs[rng.IntN(len(addrs))]
			e := uint16(rng.IntN(5))
			if rng.IntN(3) == 0 {
				e = m.Epoch()
			}
			var acts []Action
			var ev string
			slot, bits := uint8(rng.IntN(protocol.MaxPaths+1)), uint8(rng.Uint32())
			switch rng.IntN(14) {
			case 0:
				ev = "observe"
				m.Observe(now, l, r, protocol.FamilyUDP4, Kind(rng.IntN(10)))
			case 1:
				ev = "success"
				m.Success(now, l, r, protocol.FamilyUDP4, time.Duration(rng.IntN(300))*time.Millisecond)
			case 2:
				ev = "touch"
				m.Touch(now, r)
			case 3:
				ev = "nominate"
				acts = m.RecvNominate(now, e, l, r, protocol.FamilyUDP4)
			case 4:
				ev = "accept"
				acts = m.RecvAccept(now, e, r, bits)
			case 5:
				ev = "ready"
				acts = m.RecvReady(now, e, r, bits)
			case 6:
				ev = "ack"
				acts = m.RecvHandoverAck(now, e, r)
			case 7:
				ev = "upper"
				acts = m.RecvUpperLayer(now, l, r)
			case 8:
				ev = "read failed"
				acts = m.ReadFailed(now, l)
			case 9:
				ev = "extra nominate"
				acts = m.RecvExtraNominate(now, e, slot, l, r)
			case 10:
				ev = "extra accept"
				acts = m.RecvExtraAccept(now, e, slot, l, r)
			case 11:
				ev = "describe"
				kinds := []protocol.PathKind{"", protocol.PathPublic, protocol.PathLAN, protocol.PathOverlay, protocol.PathPortmap}
				m.Describe(l, r, kinds[rng.IntN(len(kinds))], uint8(rng.IntN(3)))
			default:
				ev = "tick"
				acts = m.Tick(now)
			}
			check(fmt.Sprintf("step %d %s", step, ev), acts)
		}
	}
}

// The handover under loss, duplication and reordering: both sides hand over on the
// same pair and epoch, at most once each, and the responder hands over within
// 30 ms of its Confirm when a ready got through.
func TestLossyConvergence(t *testing.T) {
	scens := []simCfg{
		{loss: 0.3, oneWay: 50 * time.Millisecond, tickStep: time.Millisecond, horizon: 10 * time.Second, paths: twoPaths()[:1], upperPTO: 200 * time.Millisecond},
		{loss: 0.3, dup: 0.1, oneWay: 40 * time.Millisecond, jitter: 30 * time.Millisecond, tickStep: time.Millisecond, horizon: 10 * time.Second, paths: twoPaths(), upperPTO: 200 * time.Millisecond},
		{loss: 0.5, dup: 0.2, oneWay: 30 * time.Millisecond, jitter: 60 * time.Millisecond, tickStep: time.Millisecond, horizon: 15 * time.Second, paths: twoPaths(), upperPTO: 200 * time.Millisecond},
		{loss: 0.3, oneWay: 350 * time.Millisecond, tickStep: time.Millisecond, horizon: 30 * time.Second, paths: twoPaths(), upperPTO: 300 * time.Millisecond},
	}
	seeds := 1000
	if testing.Short() {
		seeds = 100
	}
	for si, cfg := range scens {
		for i := range seeds {
			r := runSim(cfg, rand.New(rand.NewPCG(uint64(i), 77)))
			if r.iConfirms > 1 || r.rConfirms > 1 || r.iHandovers > 1 || r.rHandovers > 1 {
				t.Fatalf("scenario %d seed %d: confirms %d/%d handovers %d/%d", si, i, r.iConfirms, r.rConfirms, r.iHandovers, r.rHandovers)
			}
			if !r.iDone || !r.rDone || r.iPath != r.rPath || r.iEpoch != r.rEpoch {
				t.Fatalf("scenario %d seed %d: I %v R %v, paths %d/%d, epochs %d/%d\n%v",
					si, i, r.iDone, r.rDone, r.iPath, r.rPath, r.iEpoch, r.rEpoch, tail(r.log, 30))
			}
			if r.rBy == protocol.ConfirmedByReady && r.rDoneAt-r.rConfirmAt > 2*ackBurstStep {
				t.Fatalf("scenario %d seed %d: R confirmed at %v, handed over at %v", si, i, r.rConfirmAt, r.rDoneAt)
			}
		}
	}
}

// A roll that leaves only cooling-down pairs waits for the first cooldown,
// but a pair that answers in the meantime is nominated after the
// collection window, not after the cooldown; a cooling-down pair's own
// packets do not shorten the wait.
func TestFreshPairEndsCooldownWait(t *testing.T) {
	base := time.Unix(0, 0)
	loc := ap("192.0.2.1:5000")
	a, b := ap("203.0.113.9:40000"), ap("203.0.113.9:40001")
	m := NewManager(Config{Role: protocol.RoleInitiator, EpochCooldown: 2 * time.Second})
	m.Success(base, loc, a, protocol.FamilyUDP4, 40*time.Millisecond)
	var rolled time.Time
	for m.Epoch() < 2 {
		at, ok := m.NextDeadline()
		if !ok || at.Sub(base) > 5*time.Second {
			t.Fatalf("no roll: phase %v epoch %d", m.Phase(), m.Epoch())
		}
		m.Tick(at)
		if m.Phase() == PhaseCollect && m.Epoch() == 1 {
			rolled = at
			break
		}
	}
	if rolled.IsZero() {
		t.Fatalf("the roll re-nominated the cooling-down pair: epoch %d", m.Epoch())
	}
	if at, _ := m.NextDeadline(); !at.Equal(rolled.Add(2 * time.Second)) {
		t.Fatalf("waiting until %v, want the end of the cooldown %v", at, rolled.Add(2*time.Second))
	}
	m.Success(rolled.Add(5*time.Millisecond), loc, a, protocol.FamilyUDP4, 40*time.Millisecond)
	if at, _ := m.NextDeadline(); !at.Equal(rolled.Add(2 * time.Second)) {
		t.Fatalf("the cooling-down pair moved the wait to %v", at)
	}
	fresh := rolled.Add(10 * time.Millisecond)
	m.Success(fresh, loc, b, protocol.FamilyUDP4, 40*time.Millisecond)
	at, _ := m.NextDeadline()
	if want := fresh.Add(m.nomDelay()); !at.Equal(want) {
		t.Fatalf("collect at %v after a fresh pair, want %v", at, want)
	}
	if acts := m.Tick(at); count(acts, SendNominate) != 1 || acts[0].Remote != b || acts[0].Epoch != 2 {
		t.Fatalf("fresh pair not nominated: %+v", acts)
	}
}

// When the cooldown the initiator waits for ends on a pair that has closed
// meanwhile, it waits for the next cooldown instead of stalling in punching.
func TestCooldownWaitSkipsClosedPair(t *testing.T) {
	base := time.Unix(0, 0)
	l1, l2, rem := ap("192.0.2.1:5000"), ap("192.0.2.1:5001"), ap("203.0.113.9:40000")
	m := NewManager(Config{Role: protocol.RoleInitiator})
	m.Success(base, l1, rem, protocol.FamilyUDP4, 40*time.Millisecond)
	m.Success(base, l2, rem, protocol.FamilyUDP4, 40*time.Millisecond)
	m.Table().get(l1, rem).CooldownUntil = base.Add(time.Second)
	m.Table().get(l2, rem).CooldownUntil = base.Add(2 * time.Second)
	if acts := m.Tick(base.Add(100 * time.Millisecond)); len(acts) != 0 {
		t.Fatalf("nominated a cooling-down pair: %+v", acts)
	}
	if acts := m.ReadFailed(base.Add(500*time.Millisecond), l1); len(acts) != 0 {
		t.Fatalf("ReadFailed acted: %+v", acts)
	}
	if acts := m.Tick(base.Add(time.Second)); len(acts) != 0 {
		t.Fatalf("nominated at the closed pair's cooldown end: %+v", acts)
	}
	at, ok := m.NextDeadline()
	if !ok || !at.Equal(base.Add(2*time.Second)) || m.Phase() != PhaseCollect {
		t.Fatalf("phase %v, deadline %v %v; want collecting until the second cooldown ends", m.Phase(), at, ok)
	}
	if acts := m.Tick(at); count(acts, SendNominate) != 1 || acts[0].Local != l2 {
		t.Fatalf("after the second cooldown: %+v", acts)
	}
}

// Eviction does not depend on the map order: among equally useful pairs
// the address order decides, and a closed pair goes first.
func TestEvictionDeterministic(t *testing.T) {
	base := time.Unix(0, 0)
	loc := ap("192.0.2.1:5000")
	remote := func(i int) netip.AddrPort {
		return netip.AddrPortFrom(netip.AddrFrom4([4]byte{198, 51, byte(i >> 8), byte(i)}), 1)
	}
	for range 20 {
		tab := newTable()
		for i := range maxCandidates {
			tab.Success(base, loc, remote(i), protocol.FamilyUDP4, 0)
		}
		tab.Success(base, loc, ap("192.0.2.99:1"), protocol.FamilyUDP4, 0)
		if tab.get(loc, remote(0)) != nil || tab.get(loc, remote(1)) == nil || tab.Len() != maxCandidates {
			t.Fatal("evicted another pair than the first in address order")
		}
		tab.get(loc, remote(200)).State = StateClosed
		tab.Observe(base.Add(time.Second), loc, ap("192.0.2.98:1"), protocol.FamilyUDP4, KindPredicted)
		if tab.get(loc, remote(200)) != nil || tab.get(loc, remote(1)) == nil {
			t.Fatal("a closed pair outlived an open one")
		}
	}
}
