package nat

import (
	"math"
	"testing"
	"time"

	"github.com/djylb/holepunch/protocol"
)

// A signed step in send order.
func TestSequentialNegativeStep(t *testing.T) {
	f := newFixture("192.168.1.10:40000")
	f.primary("203.0.113.5:40010", "203.0.113.5:40008", "203.0.113.5:40006")
	tr := f.t.Classify()
	wantAlloc(t, tr, protocol.AllocSequential, protocol.ConfMedium)
	if tr.PortStep != -2 || tr.PortAnchor != 40006 || tr.PortVelocity != 0 || tr.PortAnchorMs != 0 {
		t.Fatalf("traits %+v", tr)
	}
	if !tr.Predictable() || tr.FirstPreserved {
		t.Fatalf("traits %+v", tr)
	}
}

// The order is the first-send order, neither the port order nor the answer
// order.
func TestStepUsesSendOrder(t *testing.T) {
	f := newFixture("192.168.1.10:40000")
	k0 := f.send(v4P, SourceServer, 0)
	k1 := f.send(v4P, SourceServer, 1)
	k2 := f.send(v4P, SourceServer, 2)
	f.t.Record(k2, ap("203.0.113.5:40006"), 30, 0, 1) // answers arrive in reverse order
	f.t.Record(k1, ap("203.0.113.5:40003"), 31, 0, 1)
	f.t.Record(k0, ap("203.0.113.5:40000"), 32, 0, 1)
	tr := f.t.Classify()
	if tr.PortAlloc != protocol.AllocSequential || tr.PortStep != 3 || tr.PortAnchor != 40006 {
		t.Fatalf("traits %+v", tr)
	}
	if !tr.FirstPreserved {
		t.Fatal("the first mapping kept the local port")
	}
}

// The step from same-socket differences, the velocity from the gap.
func TestSequentialVelocity(t *testing.T) {
	f := newFixture("192.168.1.10:40000", secondSocket())
	f.primary("203.0.113.5:50001", "203.0.113.5:50002", "203.0.113.5:50003")
	f.at += 100*time.Millisecond - time.Millisecond // the second socket's first send is 100 ms after the primary's last
	f.probe(v4S, 0, "203.0.113.5:50014")
	f.probe(v4S, 1, "203.0.113.5:50015")
	f.probe(v4S, 2, "203.0.113.5:50016")
	tr := f.t.Classify()
	wantAlloc(t, tr, protocol.AllocSequential, protocol.ConfHigh)
	if tr.PortStep != 1 || tr.PortAnchor != 50016 {
		t.Fatalf("traits %+v", tr)
	}
	if math.Abs(float64(tr.PortVelocity)-100) > 0.5 {
		t.Fatalf("velocity %v, want ≈100", tr.PortVelocity)
	}
	// a mixed difference list would see a gap of 11 and fail; a gap of the
	// opposite sign leaves the velocity unset
	f = newFixture("192.168.1.10:40000", secondSocket())
	f.primary("203.0.113.5:50001", "203.0.113.5:50002", "203.0.113.5:50003")
	f.at += 100 * time.Millisecond
	f.probe(v4S, 0, "203.0.113.5:40014")
	f.probe(v4S, 1, "203.0.113.5:40015")
	tr = f.t.Classify()
	if tr.PortAlloc != protocol.AllocSequential || tr.PortVelocity != 0 {
		t.Fatalf("traits %+v", tr)
	}
}

func TestDominantStep(t *testing.T) {
	cases := []struct {
		name string
		ds   []int
		d    int
		ok   bool
	}{
		{"two equal", []int{1, 1}, 1, true},
		{"one difference", []int{1}, 0, false},
		{"multiple of the step (a mapping in between)", []int{2, 2, 2, 4}, 2, true},
		{"multiple of the opposite sign", []int{2, 2, 2, -4}, 0, false},
		{"not a multiple, below 75%", []int{2, 2, 3}, 0, false},
		{"step > 64", []int{65, 65}, 0, false},
		{"step −64", []int{-64, -64}, -64, true},
		{"zero step", []int{0, 0}, 0, false},
		{"75% and a multiple", []int{1, 1, 1, 7}, 1, true},
		{"tie at 50%", []int{1, 2}, 0, false},
		{"alternating signs", []int{-3, 3, -3, 3}, 0, false},
	}
	for _, c := range cases {
		d, ok := dominantStep(c.ds)
		if d != c.d || ok != c.ok {
			t.Errorf("%s: dominantStep(%v) = %d, %v; want %d, %v", c.name, c.ds, d, ok, c.d, c.ok)
		}
	}
}

// Port block and random.
func TestPoolAndRandom(t *testing.T) {
	pool := []string{"203.0.113.5:31900", "203.0.113.5:32510", "203.0.113.5:31812", "203.0.113.5:32277", "203.0.113.5:32000", "203.0.113.5:32440"}
	tr := sixPorts(pool)
	wantAlloc(t, tr, protocol.AllocPool, protocol.ConfMedium)
	if tr.PortRangeLo != 31744 || tr.PortRangeHi != 32767 {
		t.Fatalf("pool [%d, %d]", tr.PortRangeLo, tr.PortRangeHi)
	}
	if !tr.Predictable() || DisplayName(tr) != "Symmetric(pool 1024)" {
		t.Fatalf("predictable=%v name=%q", tr.Predictable(), DisplayName(tr))
	}
	random := []string{"203.0.113.5:1100", "203.0.113.5:61000", "203.0.113.5:20000", "203.0.113.5:9000", "203.0.113.5:45000", "203.0.113.5:33000"}
	wantAlloc(t, sixPorts(random), protocol.AllocRandom, protocol.ConfHigh)
	// four in a block → Low; three anywhere → Random Low; five → Random Medium
	wantAlloc(t, sixPorts(pool[:4]), protocol.AllocPool, protocol.ConfLow)
	wantAlloc(t, sixPorts(random[:3]), protocol.AllocRandom, protocol.ConfLow)
	wantAlloc(t, sixPorts(random[:5]), protocol.AllocRandom, protocol.ConfMedium)
}

// sixPorts spreads the values over the primary (≤ 3) and the second socket.
func sixPorts(vals []string) protocol.Traits {
	f := newFixture("192.168.1.10:40000", secondSocket())
	for i, v := range vals {
		sock := v4P
		if i >= 3 {
			sock = v4S
		}
		f.probe(sock, uint8(i%3), v)
	}
	return f.t.Classify()
}

func TestBlockEstimate(t *testing.T) {
	if _, _, ok := blockEstimate([]uint16{1, 2, 3}); ok {
		t.Fatal("3 samples")
	}
	if _, _, ok := blockEstimate([]uint16{100, 5000, 200, 300}); ok {
		t.Fatal("span > 4096")
	}
	// a block across an alignment boundary doubles until it fits
	lo, hi, ok := blockEstimate([]uint16{1000, 1030, 1050, 1060})
	if !ok || lo > 1000 || hi < 1060 || (int(hi)-int(lo)+1)&(int(hi)-int(lo)) != 0 {
		t.Fatalf("block [%d, %d] %v", lo, hi, ok)
	}
	// the top of the port space is clamped
	lo, hi, ok = blockEstimate([]uint16{65000, 65100, 65200, 65300})
	if !ok || hi != 65535 || lo > 65000 {
		t.Fatalf("block [%d, %d] %v", lo, hi, ok)
	}
}

// An ADM NAT allocates one mapping per destination IP. With three server IPs
// (two main groups and the alt group) the per-IP sequence shows the
// allocator, so ADM can be Predictable.
func TestADMAllocation(t *testing.T) {
	obs := []Observer{
		{ID: 0, Addr: ap("198.51.100.1:3478"), Group: 0},
		{ID: 1, Addr: ap("198.51.100.1:3479"), Group: 0},
		{ID: 8, Addr: ap("198.51.100.9:3478"), Group: 1},
		{ID: 9, Addr: ap("198.51.100.9:3479"), Group: 1},
		{ID: 16, Addr: ap("198.51.100.20:3478"), Group: 2, Alt: true},
	}
	run := func(local string, main [4]string, alt string) protocol.Traits {
		tb := NewTable(protocol.FamilyUDP4, []SocketMeta{{ID: v4P, Kind: protocol.SocketPrimary, Local: ap(local)}}, obs)
		for i, o := range []uint8{0, 1, 8, 9} {
			k := PointKey{Socket: v4P, Source: SourceServer, Observer: o}
			tb.NoteSent(k, uint32(i+1), time.Duration(i))
			tb.Record(k, ap(main[i]), time.Duration(i), 0, 1)
		}
		if alt != "" {
			k := PointKey{Socket: v4P, Source: SourceServerAlt, Observer: 16}
			tb.NoteSent(k, 10, 50*time.Millisecond)
			tb.Record(k, ap(alt), 60*time.Millisecond, 0, 1)
		}
		return tb.Classify()
	}
	seq := [4]string{"203.0.113.5:6000", "203.0.113.5:6000", "203.0.113.5:6002", "203.0.113.5:6002"}
	tr := run("10.0.0.2:5000", seq, "203.0.113.5:6004")
	wantMapping(t, tr, protocol.MapADM, protocol.ConfHigh)
	wantAlloc(t, tr, protocol.AllocSequential, protocol.ConfMedium)
	if tr.PortStep != 2 || tr.PortAnchor != 6004 || !tr.Predictable() || Fingerprint(tr) != "v4|ADM|UNK|SEQ+2" {
		t.Fatalf("traits %+v (%s)", tr, Fingerprint(tr))
	}
	// two server IPs only: one difference, no allocation claim
	tr = run("10.0.0.2:5000", seq, "")
	if tr.Mapping != protocol.MapADM || tr.PortAlloc != protocol.AllocUnknown || tr.Predictable() {
		t.Fatalf("traits %+v", tr)
	}
	// the first mapping kept the local port: preserving
	tr = run("10.0.0.2:6000", seq, "203.0.113.5:6004")
	wantAlloc(t, tr, protocol.AllocPreserving, protocol.ConfHigh)
	// unrelated ports: random at Low
	tr = run("10.0.0.2:5000", [4]string{"203.0.113.5:6000", "203.0.113.5:6000", "203.0.113.5:31000", "203.0.113.5:31000"}, "203.0.113.5:2000")
	wantAlloc(t, tr, protocol.AllocRandom, protocol.ConfLow)
}

// A velocity is only read across a baseline of at least 100 ms; a
// shorter gap reads a single foreign mapping as tens of ports a second.
func TestVelocityNeedsLongBaseline(t *testing.T) {
	f := newFixture("192.168.1.10:40000", secondSocket())
	f.primary("203.0.113.5:50001", "203.0.113.5:50002", "203.0.113.5:50003")
	f.at += 15 * time.Millisecond // the second socket's first send 16 ms after the primary's last
	f.probe(v4S, 0, "203.0.113.5:50005")
	f.probe(v4S, 1, "203.0.113.5:50006")
	f.probe(v4S, 2, "203.0.113.5:50007")
	tr := f.t.Classify()
	wantAlloc(t, tr, protocol.AllocSequential, protocol.ConfHigh)
	if tr.PortVelocity != 0 || tr.PortAnchor != 50007 {
		t.Fatalf("traits %+v: a 16 ms gap gave a velocity", tr)
	}
}

// A probe lost on the way still took its port (seen in the e2e impair
// cells). The
// primary socket's middle probe got no answer: 40001 → 40003 is two sends
// and two steps, not a gap of 2 that pulls the sequence to a pool.
func TestLostProbeKeepsSequential(t *testing.T) {
	f := newFixture("192.168.1.10:40000", secondSocket())
	f.primary("203.0.113.5:40001", "", "203.0.113.5:40003")
	f.probe(v4S, 0, "203.0.113.5:40004")
	f.probe(v4S, 1, "203.0.113.5:40005")
	f.probe(v4S, 2, "203.0.113.5:40006")
	tr := f.t.Classify()
	wantAlloc(t, tr, protocol.AllocSequential, protocol.ConfHigh)
	if tr.PortStep != 1 || tr.PortAnchor != 40006 {
		t.Fatalf("traits %+v", tr)
	}
	// Without the lost probe's point in the table — a server that saw
	// nothing of it and a report that left it out — the gap is a gap.
	g := newFixture("192.168.1.10:40000", secondSocket())
	g.probe(v4P, 0, "203.0.113.5:40001")
	g.seq++ // the lost probe's seq, its point unknown
	g.probe(v4P, 2, "203.0.113.5:40003")
	g.probe(v4S, 0, "203.0.113.5:40004")
	g.probe(v4S, 1, "203.0.113.5:40005")
	g.probe(v4S, 2, "203.0.113.5:40006")
	if tr := g.t.Classify(); tr.PortAlloc == protocol.AllocSequential {
		t.Fatalf("traits %+v: a gap read as a step without its point", tr)
	}
}

// An unanswered probe between the two sockets is one of this host's
// own mappings, not another host's: the second socket's first probe was
// lost, so 50003 → 50005 over 100 ms is two own steps and no velocity.
func TestLostProbeIsNoVelocity(t *testing.T) {
	f := newFixture("192.168.1.10:40000", secondSocket())
	f.primary("203.0.113.5:50001", "203.0.113.5:50002", "203.0.113.5:50003")
	f.at += 99 * time.Millisecond
	f.probe(v4S, 0, "")
	f.probe(v4S, 1, "203.0.113.5:50005")
	f.probe(v4S, 2, "203.0.113.5:50006")
	tr := f.t.Classify()
	wantAlloc(t, tr, protocol.AllocSequential, protocol.ConfHigh)
	if tr.PortVelocity != 0 {
		t.Fatalf("velocity %v from a lost probe", tr.PortVelocity)
	}
	// An alt probe sent in the gap is an own mapping as well.
	f = newFixture("192.168.1.10:40000", secondSocket())
	f.primary("203.0.113.5:50001", "203.0.113.5:50002", "203.0.113.5:50003")
	f.at += 99 * time.Millisecond
	f.send(v4P, SourceServerAlt, 8)
	f.probe(v4S, 0, "203.0.113.5:50005")
	f.probe(v4S, 1, "203.0.113.5:50006")
	if tr := f.t.Classify(); tr.PortAlloc != protocol.AllocSequential || tr.PortVelocity != 0 {
		t.Fatalf("traits %+v with an alt probe in the gap", tr)
	}
}

// The allocator wraps from 65535 to 1024 (seen in the e2e slowctl cells);
// that is one step, not a jump that reads as Random (and could end the
// session at summary time). The same down, and across the two sockets.
func TestWrapIsOneStep(t *testing.T) {
	f := newFixture("192.168.1.10:40000", secondSocket())
	f.primary("203.0.113.5:65534", "203.0.113.5:65535", "203.0.113.5:1024")
	f.at += 99 * time.Millisecond
	f.probe(v4S, 0, "203.0.113.5:1035")
	f.probe(v4S, 1, "203.0.113.5:1036")
	f.probe(v4S, 2, "203.0.113.5:1037")
	tr := f.t.Classify()
	wantAlloc(t, tr, protocol.AllocSequential, protocol.ConfHigh)
	if tr.PortStep != 1 || tr.PortAnchor != 1037 {
		t.Fatalf("traits %+v", tr)
	}
	if math.Abs(float64(tr.PortVelocity)-100) > 0.5 { // 10 foreign ports across the wrap in 100 ms
		t.Fatalf("velocity %v, want ≈100", tr.PortVelocity)
	}
	f = newFixture("192.168.1.10:40000")
	f.primary("203.0.113.5:1025", "203.0.113.5:1024", "203.0.113.5:65535")
	if tr := f.t.Classify(); tr.PortAlloc != protocol.AllocSequential || tr.PortStep != -1 {
		t.Fatalf("down across the wrap: %+v", tr)
	}
}

// TestPortDelta: the short way round the range.
func TestPortDelta(t *testing.T) {
	for _, c := range []struct {
		a, b uint16
		d    int
	}{{1000, 1001, 1}, {65535, 1024, 1}, {1024, 65535, -1}, {40000, 30000, -10000}, {2000, 60000, 58000 - portRange}} {
		if d := portDelta(c.a, c.b); d != c.d {
			t.Errorf("portDelta(%d, %d) = %d, want %d", c.a, c.b, d, c.d)
		}
	}
}
