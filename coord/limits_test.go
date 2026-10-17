package coord

import (
	"errors"
	"fmt"
	"net/netip"
	"testing"
	"time"

	"github.com/djylb/holepunch/coord/internal/simclient"
	"github.com/djylb/holepunch/internal/nat"
	"github.com/djylb/holepunch/protocol"
)

// busy creates sessions until NewSession refuses one, and returns the
// sessions it created and the refusal.
func busy(t *testing.T, r *rig, opts SessionOptions, max int) ([]*Session, error) {
	t.Helper()
	var made []*Session
	for range max {
		s, err := r.c.NewSession(opts)
		if err != nil {
			return made, err
		}
		made = append(made, s)
	}
	return made, nil
}

// TestSessionLimits: every admission limit refuses with ErrBusy
// (server_busy) and reports the dimension.
func TestSessionLimits(t *testing.T) {
	cases := []struct {
		name string
		lim  Limits
		opts SessionOptions
		want int
		dim  string
	}{
		{"sessions", Limits{MaxSessions: 3, MaxPending: -1}, SessionOptions{}, 3, "sessions"},
		{"pending", Limits{MaxPending: 2}, SessionOptions{}, 2, "pending"},
		{"rate", Limits{NewSessions: Rate{PerSec: 1, Burst: 4}}, SessionOptions{}, 4, "rate"},
		{"initiator rate", Limits{InitiatorKeyRate: Rate{PerSec: 1, Burst: 2}}, SessionOptions{ClientKeys: [2]string{"v", ""}}, 2, "initiator_key_rate"},
		{"initiator key", Limits{MaxPerInitiatorKey: 3, InitiatorKeyRate: Rate{PerSec: -1}}, SessionOptions{ClientKeys: [2]string{"v", ""}}, 3, "initiator_key"},
		{"responder key", Limits{MaxPerResponderKey: 2}, SessionOptions{ClientKeys: [2]string{"", "p"}}, 2, "responder_key"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := newRig(t, func(cfg *Config) { cfg.Limits = c.lim })
			made, err := busy(t, r, c.opts, 50)
			if !errors.Is(err, ErrBusy) || reasonOf(err) != protocol.ReasonServerBusy || len(made) != c.want {
				t.Fatalf("made %d, err %v", len(made), err)
			}
			evs := r.waitEvents(EvRateLimited, 1)
			if len(evs) != 1 || evs[0].Data.(RateLimitedData).Dimension != c.dim {
				t.Fatalf("events %+v", evs)
			}
			if r.c.Stats().RateLimited != 1 {
				t.Fatal("not counted")
			}
			// Ending a session frees its slot (except for rates).
			made[0].Abort(protocol.ReasonCanceled, "")
			r.wait(made[0])
			if c.dim != "rate" && c.dim != "initiator_key_rate" {
				if _, err := r.c.NewSession(c.opts); err != nil {
					t.Fatalf("after release: %v", err)
				}
			}
		})
	}
}

// TestPendingLeavesOnSecondAttach: a session leaves the created/binding
// count when both sides attached.
func TestPendingLeavesOnSecondAttach(t *testing.T) {
	r := newRig(t, func(c *Config) { c.Limits.MaxPending = 1 })
	p := r.pair(SessionOptions{})
	if _, err := r.c.NewSession(SessionOptions{}); err != nil {
		t.Fatalf("pending slot not released: %v", err)
	}
	if _, err := r.c.NewSession(SessionOptions{}); !errors.Is(err, ErrBusy) {
		t.Fatalf("second pending: %v", err)
	}
	p.s.Abort(protocol.ReasonCanceled, "")
}

// TestRefusalTakesNoRate: a reservation refused by a later limit takes no
// token of its initiator key's rate.
func TestRefusalTakesNoRate(t *testing.T) {
	lim := Limits{MaxSessions: 1, MaxPending: -1, InitiatorKeyRate: Rate{PerSec: 1, Burst: 2},
		NewSessions: Rate{PerSec: -1}}.withDefaults()
	l := newLimiter(lim, time.Unix(0, 0))
	now := time.Unix(10, 0)
	keys := [2]string{"v", ""}
	q, _, err := l.reserve(now, keys)
	if err != nil {
		t.Fatal(err)
	}
	for range 5 {
		if _, dim, err := l.reserve(now, keys); !errors.Is(err, ErrBusy) || dim != "sessions" {
			t.Fatalf("over the session limit: %q %v", dim, err)
		}
	}
	l.release(now, &q)
	if _, dim, err := l.reserve(now, keys); err != nil {
		t.Fatalf("the refusals took the key's rate: %q %v", dim, err)
	}
}

// TestPacketQuota: grants are charged to the client keys; a key without
// quota left ends the punch with packet_budget_exceeded.
func TestPacketQuota(t *testing.T) {
	r := newRig(t, func(c *Config) { c.Limits.PacketsPerMinute = [2]int{64, -1} }) // under 60 left after any grant
	p := r.pair(SessionOptions{ClientKeys: [2]string{"vis", "prov"}})
	p.punching()
	if left := r.c.limiter.packetsLeft(r.clk.Now(), keyInitiator, "vis"); left != 64-grantOf(p, 0) {
		t.Fatalf("quota left %d after granting %d", left, grantOf(p, 0))
	}
	if left := r.c.limiter.packetsLeft(r.clk.Now(), keyResponder, "prov"); left != -1 {
		t.Fatalf("unlimited responder key: %d", left)
	}
	p.endRound(1, [2]simclient.Outcome{fired(5), fired(5)})
	if res := r.wait(p.s); res.Reason != protocol.ReasonPacketBudgetExceeded {
		t.Fatalf("result %+v", res)
	}
}

// TestKeyTableSweep: idle key entries are kept for two minutes with full
// buckets, then dropped; ActiveByKey counts entries in use.
func TestKeyTableSweep(t *testing.T) {
	r := newRig(t)
	s := r.session(SessionOptions{ClientKeys: [2]string{"a", "b"}})
	if r.c.Stats().ActiveByKey != 2 {
		t.Fatalf("active keys %d", r.c.Stats().ActiveByKey)
	}
	s.Abort(protocol.ReasonCanceled, "")
	r.wait(s)
	if r.c.Stats().ActiveByKey != 0 {
		t.Fatal("key still active")
	}
	now := r.clk.Now()
	if n := r.c.limiter.sweep(now); n != 0 {
		t.Fatalf("swept %d entries before the idle time", n)
	}
	if n := r.c.limiter.sweep(now.Add(keyIdleKeep + time.Minute)); n != 2 {
		t.Fatalf("swept %d entries", n)
	}
}

func TestBucket(t *testing.T) {
	t0 := time.Unix(1000, 0)
	b := newBucket(Rate{PerSec: 2, Burst: 2}, t0)
	for range 2 {
		if ok, _ := b.take(t0, 1); !ok {
			t.Fatal("burst")
		}
	}
	if ok, wait := b.take(t0, 1); ok || wait != 500*time.Millisecond {
		t.Fatalf("empty bucket: %v %v", ok, wait)
	}
	if ok, _ := b.take(t0.Add(500*time.Millisecond), 1); !ok {
		t.Fatal("refill")
	}
	if !b.full(t0.Add(time.Hour)) || b.level(t0.Add(time.Hour)) != 2 {
		t.Fatal("full")
	}
	b.take(t0.Add(time.Hour), 2)
	if ok, _ := b.take(t0, 1); ok { // the clock stepped back: no tokens appear
		t.Fatal("tokens from a clock step back")
	}
	z := newBucket(Rate{PerSec: 0, Burst: 1}, t0)
	z.take(t0, 1)
	if ok, wait := z.take(t0, 1); ok || wait != time.Hour {
		t.Fatalf("zero rate: %v %v", ok, wait)
	}
	u := newBucket(Rate{PerSec: -1}, t0)
	if ok, _ := u.take(t0, 1e9); !ok || u.level(t0) != -1 || !u.full(t0) {
		t.Fatal("unlimited")
	}
}

func TestExtremeAllowance(t *testing.T) {
	lim := Limits{ExtremePerHour: 1, MaxPerInitiatorKey: -1, MaxPerResponderKey: -1,
		InitiatorKeyRate: Rate{PerSec: -1}, NewSessions: Rate{PerSec: -1}}.withDefaults()
	l := newLimiter(lim, time.Unix(0, 0))
	now := time.Unix(10, 0)
	// The allowance belongs to the keys sessions hold.
	for _, keys := range [][2]string{{"a", "b"}, {"a", "c"}, {"", "c"}, {"d", "b"}, {"d", ""}} {
		if _, _, err := l.reserve(now, keys); err != nil {
			t.Fatal(err)
		}
	}
	if !l.takeExtreme(now, [2]string{"a", "b"}) {
		t.Fatal("first extreme")
	}
	if l.takeExtreme(now, [2]string{"a", "c"}) {
		t.Fatal("key a used twice in an hour")
	}
	// The refusal took nothing from c.
	if !l.takeExtreme(now, [2]string{"", "c"}) {
		t.Fatal("key c lost its allowance")
	}
	// The responder key b refuses: d keeps its allowance.
	if l.takeExtreme(now, [2]string{"d", "b"}) || !l.takeExtreme(now, [2]string{"d", ""}) {
		t.Fatal("refund")
	}
	if !l.takeExtreme(now.Add(time.Hour), [2]string{"a", ""}) {
		t.Fatal("allowance not refilled")
	}
	if l.noteOutcome("", true) != 0 || l.noteOutcome("a", true) != 1 || l.noteOutcome("a", true) != 2 ||
		l.noteOutcome("a", false) != 0 || l.noteOutcome("nobody", true) != 0 {
		t.Fatal("streak")
	}
	if l.packetsLeft(now, keyInitiator, "nobody") != -1 {
		t.Fatal("quota of a key no session holds")
	}
}

// keyLimiter is a limiter whose only limit is a key table of max entries.
func keyLimiter(max int) *limiter {
	lim := Limits{MaxKeys: max, MaxSessions: -1, MaxPending: -1, MaxPerInitiatorKey: -1, MaxPerResponderKey: -1,
		InitiatorKeyRate: Rate{PerSec: -1}, NewSessions: Rate{PerSec: -1}}.withDefaults()
	return newLimiter(lim, time.Unix(0, 0))
}

func (l *limiter) hasKey(role int, key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.keys[keyOf(role, key)] != nil
}

// TestKeyTableBound: the quota table never holds more than MaxKeys entries,
// however many keys come and go; the default is 65536 and cannot be removed.
func TestKeyTableBound(t *testing.T) {
	if got := (Limits{MaxKeys: -1}).withDefaults().MaxKeys; got != defMaxKeys || (Limits{}).withDefaults().MaxKeys != 65536 {
		t.Fatalf("MaxKeys default %d", got)
	}
	l := keyLimiter(8)
	now := time.Unix(100, 0)
	for i := range 1000 {
		q, _, err := l.reserve(now, [2]string{fmt.Sprint("i", i), fmt.Sprint("r", i)})
		if err != nil {
			t.Fatalf("session %d: %v", i, err)
		}
		if entries, active, _, _ := l.keyStats(); entries > 8 || active != 2 {
			t.Fatalf("session %d: %d entries, %d active", i, entries, active)
		}
		l.release(now, &q)
		now = now.Add(time.Millisecond)
	}
	if entries, active, evicted, full := l.keyStats(); entries != 8 || active != 0 || evicted != 2000-8 || full != 0 {
		t.Fatalf("entries %d active %d evicted %d full %d", entries, active, evicted, full)
	}
}

// TestKeyTableEviction: a new key in a full table evicts the entry idle the
// longest; a held entry is never evicted, and an entry used again goes to
// the back of the idle order.
func TestKeyTableEviction(t *testing.T) {
	l := keyLimiter(4)
	now := time.Unix(100, 0)
	qs := map[string]quota{}
	for _, k := range []string{"a", "b", "c", "d"} {
		q, _, err := l.reserve(now, [2]string{k, ""})
		if err != nil {
			t.Fatal(err)
		}
		qs[k] = q
	}
	// Idle order: b, d, a; c stays held.
	for _, k := range []string{"b", "d", "a"} {
		now = now.Add(time.Second)
		q := qs[k]
		l.release(now, &q)
	}
	// b is used again and released: the order becomes d, a, b.
	q, _, _ := l.reserve(now, [2]string{"b", ""})
	now = now.Add(time.Second)
	l.release(now, &q)
	for _, c := range []struct{ add, gone string }{{"e", "d"}, {"f", "a"}, {"g", "b"}} {
		q, _, err := l.reserve(now, [2]string{c.add, ""})
		if err != nil {
			t.Fatalf("%s: %v", c.add, err)
		}
		if l.hasKey(keyInitiator, c.gone) || !l.hasKey(keyInitiator, c.add) || !l.hasKey(keyInitiator, "c") {
			t.Fatalf("adding %s did not evict %s alone", c.add, c.gone)
		}
		l.release(now, &q)
		now = now.Add(time.Second)
	}
	// The sweep walks the same order: e, f and g are idle and full.
	if n := l.sweep(now.Add(keyIdleKeep)); n != 3 || !l.hasKey(keyInitiator, "c") {
		t.Fatalf("swept %d", n)
	}
}

// TestKeyTableFull: with every entry held by a live session, a session with
// a new key is refused with ErrBusy (dimension keys) and counted; one with a
// held key still gets in, and so does a new key once a session ends.
func TestKeyTableFull(t *testing.T) {
	r := newRig(t, func(c *Config) { c.Limits.MaxKeys = 3; c.Limits.MaxPerInitiatorKey = -1 })
	var live []*Session
	for _, keys := range [][2]string{{"a", "b"}, {"c", ""}} {
		live = append(live, r.session(SessionOptions{ClientKeys: keys}))
	}
	_, err := r.c.NewSession(SessionOptions{ClientKeys: [2]string{"x", ""}})
	if !errors.Is(err, ErrBusy) || reasonOf(err) != protocol.ReasonServerBusy {
		t.Fatalf("new key in a full table: %v", err)
	}
	st := r.c.Stats()
	if st.KeyTableFull != 1 || st.RateLimited != 1 || st.KeyEntries != 3 || st.ActiveByKey != 3 {
		t.Fatalf("stats %+v", st)
	}
	ev := r.waitEvents(EvRateLimited, 1)
	if d := ev[0].Data.(RateLimitedData); d.Dimension != "keys" {
		t.Fatalf("event %+v", d)
	}
	live = append(live, r.session(SessionOptions{ClientKeys: [2]string{"a", ""}}))
	live[1].Abort(protocol.ReasonCanceled, "")
	r.wait(live[1])
	live = append(live, r.session(SessionOptions{ClientKeys: [2]string{"x", ""}}))
	if st := r.c.Stats(); st.KeysEvicted != 1 || st.KeyEntries != 3 {
		t.Fatalf("stats %+v", st)
	}
	for _, s := range live {
		s.Abort(protocol.ReasonCanceled, "")
		r.wait(s)
	}
}

// TestCandidateTimeoutBackoff: three candidate_timeout results in a row for a
// key raise the retry advice to 15 s, doubling to 2 min.
func TestCandidateTimeoutBackoff(t *testing.T) {
	cases := []struct {
		streak int
		want   time.Duration
	}{{1, time.Second}, {2, time.Second}, {3, 15 * time.Second}, {4, 30 * time.Second}, {9, 2 * time.Minute}}
	for _, c := range cases {
		if got := retryFor(protocol.ReasonCandidateTimeout, "", c.streak); got.After != c.want {
			t.Errorf("streak %d: %v", c.streak, got)
		}
	}
	for code, want := range map[protocol.Reason]RetryAdvice{
		protocol.ReasonPeerOffline:          {Retryable: true, After: retryDisconnect},
		protocol.ReasonLocalPortBindFailed:  {Retryable: true, After: 5 * time.Second},
		protocol.ReasonOneWayUDPOnly:        {Retryable: true, After: 15 * time.Second},
		protocol.ReasonHardSymmetricRandom:  {Retryable: false, After: 0},
		protocol.ReasonProtocolViolation:    {Retryable: false, After: 0},
		protocol.ReasonHandoverTimeout:      {Retryable: true, After: time.Second},
		protocol.ReasonServerShutdown:       {Retryable: true, After: 0},
		protocol.ReasonNoProbeEndpoint:      {Retryable: false, After: 0},
		protocol.ReasonControlTimeout:       {Retryable: true, After: time.Second},
		protocol.ReasonControlInterrupted:   {Retryable: true, After: 0},
		protocol.ReasonPacketBudgetExceeded: {Retryable: true, After: time.Minute},
	} {
		if got := retryFor(code, "", 0); got != want {
			t.Errorf("%s: %+v, want %+v", code, got, want)
		}
	}
	if got := retryFor(protocol.ReasonPeerOffline, detailJoinTimeout, 0); got.After != 0 || !got.Retryable {
		t.Errorf("join timeout: %+v", got)
	}
	if got := retryFor(protocol.ReasonPeerOffline, detailStalled, 0); got.After != time.Second {
		t.Errorf("stalled: %+v", got)
	}
	if retryFor("", "", 0).Retryable {
		t.Error("success retryable")
	}
}

func TestOutcomeOf(t *testing.T) {
	for code, want := range map[protocol.Reason]Outcome{
		"":                                 OutcomeSucceeded,
		protocol.ReasonCandidateTimeout:    OutcomeFailed,
		protocol.ReasonNotSynchronized:     OutcomeFailed,
		protocol.ReasonTransportMismatch:   OutcomeFailed,
		protocol.ReasonControlInterrupted:  OutcomeAborted,
		protocol.ReasonServerBusy:          OutcomeAborted,
		protocol.ReasonInternal:            OutcomeAborted,
		protocol.ReasonHardSymmetricRandom: OutcomeFailed,
	} {
		if got := outcomeOf(code); got != want {
			t.Errorf("%q: %v", code, got)
		}
	}
	for _, o := range []Outcome{OutcomeSucceeded, OutcomeFailed, OutcomeAborted, 0} {
		if o.String() == "" {
			t.Error("empty name")
		}
	}
}

// TestMemoryBounds: every table of the coordinator that grows with its
// input has an explicit cap. The session index (MaxSessions) and the key
// table (MaxKeys) cannot be removed; a session queues at most four
// port-mapping and four drift peer_targets per side and pushes at most 16
// drifted mappings in all.
func TestMemoryBounds(t *testing.T) {
	lim := (Limits{MaxSessions: -1, MaxKeys: -1}).withDefaults()
	if lim.MaxSessions != defMaxSessions || lim.MaxKeys != defMaxKeys {
		t.Fatalf("removable bounds: %+v", lim)
	}
	_, s := testSession(t)
	s.mu.Lock()
	defer s.mu.Unlock()
	st := &s.st
	u4 := protocol.FamilyUDP4
	var drift [2][]nat.Observation
	for i := range 40 {
		drift[0] = append(drift[0], nat.Observation{Socket: nat.SocketID(u4, nat.IndexPrimary),
			Observed: netip.AddrPortFrom(pubI.Addr(), uint16(1000+i)), Changes: 1})
	}
	for range 6 {
		s.takeDriftLocked(drift)
		if len(st.pending[1]) > maxQueuedAssists || len(st.drifted) > maxDrifted {
			t.Fatalf("%d drift targets queued, %d drifted", len(st.pending[1]), len(st.drifted))
		}
		st.pending[1] = nil // what a go does
	}
	if len(st.drifted) != maxDrifted {
		t.Fatalf("%d drifted", len(st.drifted))
	}
	st.pair.SamePublicIP = map[protocol.Family]bool{u4: true}
	st.portmap[1] = make([]protocol.Assist, maxQueuedAssists)
	s.latePortMapLocked(0, u4, protocol.PortMapReport{External: mustAP("100.64.1.1:4000")}, 0)
	if len(st.portmap[1]) != maxQueuedAssists {
		t.Fatalf("%d port mappings queued", len(st.portmap[1]))
	}
}
