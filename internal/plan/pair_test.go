package plan

import (
	"fmt"
	"slices"
	"testing"
)

// TestPairOrders checks the two orders of a paired stage:
// deterministic per seed and different across seeds, permutations without a
// run of three, max(n/8, 4) exact pairs, a pair for every shift up to four
// in a window of at least 16, and pairs for most shifts up to five.
func TestPairOrders(t *testing.T) {
	for _, n := range []int{1, 2, 3, 4, 5, 8, 15, 16, 17, 19, 24, 32, 45, 46, 48, 128} {
		shifted := 0
		distinct := map[string]bool{}
		const seeds = 64
		for s := range seeds {
			seed := [8]byte{byte(s), byte(s >> 8), byte(n)}
			pi, tau := pairOrders(seed, n)
			pi2, tau2 := pairOrders(seed, n)
			if !slices.Equal(pi, pi2) || !slices.Equal(tau, tau2) {
				t.Fatalf("n=%d seed %d: not deterministic", n, s)
			}
			distinct[fmt.Sprint(pi, tau)] = true
			if !isPerm(pi) || !isPerm(tau) {
				t.Fatalf("n=%d seed %d: not permutations: %v %v", n, s, pi, tau)
			}
			if permRun(pi) > 2 || permRun(tau) > 2 {
				t.Fatalf("n=%d seed %d: run of three: %v %v", n, s, pi, tau)
			}
			if got, want := pairs(pi, tau, 0, 0), max(n/8, min(n, minExactPair)); got < want {
				t.Fatalf("n=%d seed %d: %d exact pairs, want >= %d", n, s, got, want)
			}
			if n < minPairSpan {
				continue
			}
			for dI := range minPairShift + 1 {
				for dR := range minPairShift + 1 {
					if pairs(pi, tau, dI, dR) == 0 {
						t.Errorf("n=%d seed %d: no pair for shifts (%d, %d)", n, s, dI, dR)
					}
				}
			}
			for dI := range maxPairShift + 1 {
				for dR := range maxPairShift + 1 {
					if pairs(pi, tau, dI, dR) > 0 {
						shifted++
					}
				}
			}
		}
		if n >= 8 && len(distinct) < seeds*3/4 { // few short orders exist
			t.Errorf("n=%d: %d distinct order pairs over %d seeds", n, len(distinct), seeds)
		}
		// 36 shifts up to five; a window of 46 has room for each of them.
		if n >= 46 && shifted < seeds*36*9/10 {
			t.Errorf("n=%d: %d of %d shifts up to five paired", n, shifted, seeds*36)
		}
	}
}

// pairs counts the initiator positions j whose mapping and the responder
// mapping it targets target each other when the two NATs run dI and dR
// positions ahead of the predictions.
func pairs(pi, tau []int, dI, dR int) int {
	n, m := len(pi), 0
	for j, p := range pi {
		if x := p - dR; j+dI < n && x >= 0 && x < n && tau[x] == j+dI {
			m++
		}
	}
	return m
}

func isPerm(p []int) bool {
	seen := make([]bool, len(p))
	for _, x := range p {
		if x < 0 || x >= len(p) || seen[x] {
			return false
		}
		seen[x] = true
	}
	return true
}

// simulatePair runs two sequential NATs (step 1) through one paired round:
// each side's j-th paired packet takes its NAT's next port after aLast and
// bLast plus the side's unseen allocations dI and dR, while the peer
// predicts aLast and bLast; it returns how many mapping pairs target each
// other.
func simulatePair(seed [8]byte, span int, aLast, bLast uint16, dI, dR int) int {
	init := ExpandPaired(bLast, []int16{1}, span, ExpandInput{PairSeed: seed})
	resp := ExpandPaired(aLast, []int16{1}, span, ExpandInput{PairSeed: seed, Responder: true})
	aTo := map[uint16]uint16{} // initiator mapping -> the responder port it targets
	for j, p := range init {
		aTo[aLast+uint16(dI+j+1)] = p
	}
	met := 0
	for i, p := range resp {
		if aTo[p] == bLast+uint16(dR+i+1) {
			met++
		}
	}
	return met
}

// TestExpandPairedNATs: with exact predictions the reserved exact pairs
// meet; with a few allocations each prediction missed, the reserved shift
// pairs still meet; and a filtered port is replaced beyond the window, so
// that the positions behind it stay aligned.
func TestExpandPairedNATs(t *testing.T) {
	const span = 16
	aLast, bLast := uint16(20000), uint16(30000)
	for s := range 32 {
		seed := [8]byte{9, byte(s)}
		if met := simulatePair(seed, span, aLast, bLast, 0, 0); met < minExactPair {
			t.Fatalf("seed %d: %d pairs met, want >= %d", s, met, minExactPair)
		}
		for _, sh := range [][2]int{{1, 0}, {0, 1}, {2, 2}, {2, 0}} {
			if met := simulatePair(seed, span, aLast, bLast, sh[0], sh[1]); met == 0 {
				t.Errorf("seed %d: no pair met with shifts %v", s, sh)
			}
		}
	}
	// A filtered port (here: already sent) is replaced beyond the window; the
	// others keep their positions.
	seed := [8]byte{1}
	plain := ExpandPaired(bLast, []int16{1}, span, ExpandInput{PairSeed: seed})
	sent := bLast + 3
	got := ExpandPaired(bLast, []int16{1}, span, ExpandInput{PairSeed: seed, Exclude: func(p uint16) bool { return p == sent }})
	if len(got) != span {
		t.Fatalf("%d ports, want %d", len(got), span)
	}
	for j, p := range got {
		switch {
		case plain[j] == sent && p != bLast+span+2:
			t.Errorf("position %d: substitute %d, want %d", j, p, bLast+span+2)
		case plain[j] != sent && p != plain[j]:
			t.Errorf("position %d: %d moved to %d", j, plain[j], p)
		}
	}
}

// TestExpandPairedWrap: a window past 65535 wraps into [1024, 65535], as a
// sequential allocator does, and stays free of runs of three; a negative
// step goes down.
func TestExpandPairedWrap(t *testing.T) {
	got := ExpandPaired(65530, []int16{1}, 16, ExpandInput{PairSeed: [8]byte{3}})
	want := map[uint16]bool{}
	for k := 1; k <= 16; k++ {
		want[wrapPort(65530+k)] = true
	}
	for _, p := range got {
		if !want[p] {
			t.Fatalf("port %d outside the wrapped window: %v", p, got)
		}
	}
	if !want[1024] || !want[1034] || len(got) != 16 || MaxConsecutiveRun(got) > 2 {
		t.Fatalf("wrapped window %v", got)
	}
	down := ExpandPaired(30000, []int16{-1}, 8, ExpandInput{PairSeed: [8]byte{3}})
	for _, p := range down {
		if p < 29992 || p > 29999 {
			t.Fatalf("negative step: port %d outside [29992, 29999]", p)
		}
	}
	if wrapPort(1023) != 65535 || wrapPort(65536) != 1024 || wrapPort(40000) != 40000 {
		t.Fatal("wrapPort")
	}
}

// FuzzExpandPaired: whatever the seed, anchor, step, span and filter, a
// paired stage emits at most span unique ports, none sensitive or below
// 1024, no run of more than three consecutive ports — none of three
// for a step of at most 16, so the send gate never reorders it —
// and both roles aim at the same ports.
func FuzzExpandPaired(f *testing.F) {
	f.Add(uint64(1), uint16(40000), int16(1), uint16(16), uint16(0))
	f.Add(uint64(9), uint16(65530), int16(1), uint16(105), uint16(3))
	f.Add(uint64(3), uint16(1400), int16(-2), uint16(128), uint16(7))
	f.Add(uint64(5), uint16(1), int16(64), uint16(600), uint16(1))
	f.Fuzz(func(t *testing.T, seedN uint64, anchor uint16, step int16, span uint16, every uint16) {
		span %= 600
		var seed [8]byte
		for i := range seed {
			seed[i] = byte(seedN >> (8 * i))
		}
		// every > 1 filters one port in every: as if already sent.
		excl := func(p uint16) bool { return every > 1 && p%every == 0 }
		var both [2][]uint16
		for r := range 2 {
			ports := ExpandPaired(anchor, []int16{step}, int(span), ExpandInput{PairSeed: seed, Responder: r == 1, Exclude: excl})
			if len(ports) > int(span) {
				t.Fatalf("%d ports > span %d", len(ports), span)
			}
			seen := map[uint16]bool{}
			for _, p := range ports {
				if p < minUserPort || SensitivePort(p) || seen[p] || excl(p) {
					t.Fatalf("port %d filtered or repeated: %v", p, ports)
				}
				seen[p] = true
			}
			if run := MaxConsecutiveRun(ports); run > 3 || run > 2 && step >= -16 && step <= 16 {
				t.Fatalf("step %d: run %d: %v", step, run, ports)
			}
			both[r] = slices.Sorted(slices.Values(ports))
		}
		if !slices.Equal(both[0], both[1]) {
			t.Fatalf("the two roles aim at different ports: %v / %v", both[0], both[1])
		}
	})
}
