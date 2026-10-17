package plan

import (
	"net/netip"
	"slices"
	"testing"

	"github.com/djylb/holepunch/internal/udpwire"
	"github.com/djylb/holepunch/protocol"
)

// spraySeed builds a spray seed the way the client would, from the one KDF
// (udpwire.SpraySeed); the plan package itself never computes it.
func spraySeed(token byte, role udpwire.Role, round uint8, seed uint32) [8]byte {
	var tk [32]byte
	var rt [udpwire.RouteSize]byte
	for i := range tk {
		tk[i] = token
	}
	for i := range rt {
		rt[i] = token ^ 0x5a
	}
	return udpwire.SpraySeed(tk, rt, role, round, seed)
}

// The same (token, route, role, round, seed) reproduces the same sequence
// on both peers; a different session, round or role differs.
func TestExpandDeterministicAcrossPeers(t *testing.T) {
	ip := netip.MustParseAddr("203.0.113.9")
	st := protocol.Stage{Kind: protocol.StageRandom, IP: ip, Count: 200}

	s1 := spraySeed(0x11, udpwire.RoleInitiator, 1, 12345)
	s1b := spraySeed(0x11, udpwire.RoleInitiator, 1, 12345)
	a := ExpandStage(st, ExpandInput{Seed: s1})
	b := ExpandStage(st, ExpandInput{Seed: s1b})
	if !slices.Equal(a, b) {
		t.Fatal("same inputs produced different sequences")
	}
	if len(a) != 200 {
		t.Fatalf("got %d ports, want 200", len(a))
	}
	diffRound := ExpandStage(st, ExpandInput{Seed: spraySeed(0x11, udpwire.RoleInitiator, 2, 12345)})
	diffSess := ExpandStage(st, ExpandInput{Seed: spraySeed(0x22, udpwire.RoleInitiator, 1, 12345)})
	diffRole := ExpandStage(st, ExpandInput{Seed: spraySeed(0x11, udpwire.RoleResponder, 1, 12345)})
	if slices.Equal(a, diffRound) || slices.Equal(a, diffSess) || slices.Equal(a, diffRole) {
		t.Fatal("different session/round/role must differ")
	}
}

func TestRandomConstraints(t *testing.T) {
	for r := byte(0); r < 40; r++ {
		seed := spraySeed(r, udpwire.RoleInitiator, 1, uint32(r)*7+1)
		ports := ExpandRandom(0, 0, 300, ExpandInput{Seed: seed, StageIndex: int(r),
			Exclude: func(p uint16) bool { return p%50 == 0 }})
		seen := map[uint16]struct{}{}
		for _, p := range ports {
			if p < 1024 || SensitivePort(p) || p%50 == 0 {
				t.Fatalf("bad random port %d", p)
			}
			if _, dup := seen[p]; dup {
				t.Fatalf("duplicate port %d", p)
			}
			seen[p] = struct{}{}
		}
		if run := MaxConsecutiveRun(ports); run > 3 {
			t.Fatalf("consecutive run %d > 3", run)
		}
	}
}

func TestPredictConstraints(t *testing.T) {
	for r := byte(0); r < 40; r++ {
		seed := spraySeed(r, udpwire.RoleResponder, 2, uint32(r)*13+5)
		ports := ExpandPredict(40000, []int16{2}, 128, ExpandInput{Seed: seed, StageIndex: int(r)})
		if len(ports) == 0 {
			t.Fatal("no predicted ports")
		}
		seen := map[uint16]struct{}{}
		for _, p := range ports {
			if p < 1024 || SensitivePort(p) {
				t.Fatalf("bad predicted port %d", p)
			}
			if _, dup := seen[p]; dup {
				t.Fatalf("duplicate predicted port %d", p)
			}
			seen[p] = struct{}{}
		}
		if run := MaxConsecutiveRun(ports); run > 3 {
			t.Fatalf("consecutive run %d > 3", run)
		}
	}
}

// A window of several steps is filled from all of them: a large step
// does not end the sweep while a smaller one still has ports to add.
func TestPredictSeveralSteps(t *testing.T) {
	for _, steps := range [][]int16{{1, 30000}, {30000, -2}, {-7, 1000, 3}} {
		got := predictPortValues(40000, steps, 200, func(p uint16) bool { return avoidPort(p, nil) })
		if len(got) != 200 {
			t.Errorf("steps %v: %d ports, want 200", steps, len(got))
		}
	}
}

// The consecutive-run <= 3 constraint is HARD, including dense small sets
// (predict step 1 with narrow spans, and pools whose size equals the count).
func TestConsecutiveRunDenseHard(t *testing.T) {
	for s := 0; s < iterations(5000); s++ {
		seed := [8]byte{byte(s), byte(s >> 8), byte(s >> 16), 7}
		for _, span := range []int{4, 5, 6, 7, 8, 9, 12, 16, 32, 48} {
			p := ExpandPredict(40000, []int16{1}, span, ExpandInput{Seed: seed})
			if r := MaxConsecutiveRun(p); r > 3 {
				t.Fatalf("predict span=%d seed=%d: run %d: %v", span, s, r, p)
			}
		}
		for _, n := range []int{4, 5, 6, 8, 10, 16} {
			r := ExpandRandom(40000, uint16(40000+n-1), n, ExpandInput{Seed: seed})
			if m := MaxConsecutiveRun(r); m > 3 {
				t.Fatalf("random pool=%d seed=%d: run %d: %v", n, s, m, r)
			}
		}
	}
}

// A fully consecutive hostile input is reordered to a run of <= 3.
func TestLimitConsecutiveHostile(t *testing.T) {
	in := make([]uint16, 0, 500)
	for p := uint16(2000); p < 2500; p++ {
		in = append(in, p)
	}
	seed := spraySeed(0x7e, udpwire.RoleInitiator, 1, 99)
	r := substream(seed, "test", 0)
	out := limitConsecutive(r, in)
	if len(out) != len(in) {
		t.Fatalf("length changed: %d != %d", len(out), len(in))
	}
	if run := MaxConsecutiveRun(out); run > 3 {
		t.Fatalf("consecutive run %d > 3", run)
	}
}

func TestDirectOffsets(t *testing.T) {
	seed := spraySeed(0x33, udpwire.RoleInitiator, 1, 7)
	offs := DirectOffsets(seed, 0, 0, 8)
	if len(offs) != 8 {
		t.Fatalf("len=%d", len(offs))
	}
	if offs[0] != 0 {
		t.Fatalf("offs[0]=%v, want 0", offs[0])
	}
	for i := 1; i < len(offs); i++ {
		if offs[i] <= offs[i-1] {
			t.Fatalf("offsets not increasing at %d: %v", i, offs)
		}
	}
	if !slices.Equal(offs, DirectOffsets(seed, 0, 0, 8)) {
		t.Fatal("offsets not deterministic")
	}
	if slices.Equal(offs, DirectOffsets(seed, 0, 1, 8)) {
		t.Fatal("different target index should differ")
	}
}

// RangeCapacity caps a grant to the ports a pool can actually emit.
func TestRangeCapacity(t *testing.T) {
	// [40000,40099] has 100 ports, none sensitive or sub-1024.
	if n := RangeCapacity(40000, 40099, nil); n != 100 {
		t.Fatalf("RangeCapacity = %d, want 100", n)
	}
	got := ExpandRandom(40000, 40099, 368, ExpandInput{Seed: [8]byte{1}})
	if len(got) > 100 {
		t.Fatalf("expanded %d ports from a 100-port pool", len(got))
	}
}

func iterations(n int) int {
	if testing.Short() {
		return n / 10
	}
	return n
}

// RangeCapacity's closed form equals counting the range port by port,
// for ranges around every sensitive port, the full range and allow sets.
func TestRangeCapacityClosedForm(t *testing.T) {
	brute := func(lo, hi uint16, allow map[uint16]struct{}) int {
		if lo < minUserPort {
			lo = minUserPort
		}
		if hi == 0 || hi < lo {
			hi = 65535
		}
		n := 0
		for p := int(lo); p <= int(hi); p++ {
			if !avoidPort(uint16(p), allow) {
				n++
			}
		}
		return n
	}
	var listed []uint16
	for p := minUserPort; p <= 65535; p++ {
		if SensitivePort(uint16(p)) {
			listed = append(listed, uint16(p))
		}
	}
	if got := sensitiveUserPorts(); !slices.Equal(got[:], listed) {
		t.Fatalf("sensitiveUserPorts %v, SensitivePort above 1023 %v", got, listed)
	}
	allows := []map[uint16]struct{}{nil, {1900: {}, 5353: {}}, {11211: {}, 40000: {}, 80: {}}}
	ranges := [][2]uint16{{0, 0}, {0, 1023}, {1024, 65535}, {65535, 65535}, {40000, 30000}, {500, 2000}}
	for _, p := range listed {
		ranges = append(ranges, [2]uint16{p, p}, [2]uint16{p - 1, p + 1}, [2]uint16{p + 1, p + 100})
	}
	for _, r := range ranges {
		for _, allow := range allows {
			if got, want := RangeCapacity(r[0], r[1], allow), brute(r[0], r[1], allow); got != want {
				t.Fatalf("RangeCapacity(%d, %d, %v) = %d, want %d", r[0], r[1], allow, got, want)
			}
		}
	}
}

// A peer_targets window leaves in the order of the spray seed — a
// permutation of its ports with no run of more than three, the same for the
// same seed and index, different for another session, round, role or index.
func TestScatterPorts(t *testing.T) {
	window := make([]uint16, 64)
	for i := range window {
		window[i] = uint16(5000 + i)
	}
	orig := slices.Clone(window)
	seed := spraySeed(0x31, udpwire.RoleInitiator, 2, 99)
	a := ScatterPorts(seed, 0, window)
	if !slices.Equal(window, orig) {
		t.Fatal("input modified")
	}
	if got := slices.Sorted(slices.Values(a)); !slices.Equal(got, orig) {
		t.Fatalf("not a permutation: %v", a)
	}
	if slices.Equal(a, orig) || MaxConsecutiveRun(a) > 3 {
		t.Fatalf("order %v (run %d)", a, MaxConsecutiveRun(a))
	}
	if !slices.Equal(a, ScatterPorts(seed, 0, window)) {
		t.Fatal("not deterministic")
	}
	for _, other := range [][]uint16{
		ScatterPorts(seed, 1, window),
		ScatterPorts(spraySeed(0x31, udpwire.RoleInitiator, 3, 99), 0, window),
		ScatterPorts(spraySeed(0x31, udpwire.RoleResponder, 2, 99), 0, window),
		ScatterPorts(spraySeed(0x32, udpwire.RoleInitiator, 2, 99), 0, window),
	} {
		if slices.Equal(a, other) {
			t.Fatal("another index, round, role or session gave the same order")
		}
	}
	// small windows are shuffled too, and every run stays within three
	for n := range 9 {
		for r := range 50 {
			w := orig[:n]
			out := ScatterPorts(spraySeed(byte(r), udpwire.RoleInitiator, 1, uint32(n)), r, w)
			if len(out) != n || MaxConsecutiveRun(out) > 3 {
				t.Fatalf("window of %d: %v", n, out)
			}
		}
	}
	if len(ScatterPorts(seed, 0, nil)) != 0 {
		t.Fatal("empty window")
	}
}
