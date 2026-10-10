package plan

import (
	"math/rand/v2"
	"slices"
)

// A paired predict stage (protocol.Stage.Pair) is the predict stage of
// seq_x_seq. Both sides sit
// behind sequential endpoint-dependent NATs: each new destination takes the
// next port. The planner aims each side's window at exactly the ports the
// peer's own predict stage of the round allocates, in the same span, so the
// i-th position of a side's window is the peer's i-th predict mapping. A
// packet only gets through when the two mappings target each other, and
// with two independently shuffled orders that happens about as often as a
// random permutation has a fixed point (1 − 1/e per round at best). So the
// two orders are drawn together, from one seed both sides know — the
// initiator's spray seed of the round — such that many positions pair up.

// Pairing parameters.
const (
	maxPairTries = 256
	maxPairShift = 5  // the largest unseen allocation count a pair is reserved for
	minPairShift = 4  // shifts up to this one always get a pair in a window of minPairSpan
	minPairSpan  = 16 // the first rung's predict span
	minExactPair = 4  // exact pairs: max(n/8, minExactPair), at most n
	// maxSubstitutes bounds the search for a free port after a paired
	// window.
	maxSubstitutes = 4096
	// maxCoverSwaps bounds the local search of one draw (coverShifts): a
	// window of 16 needs some 1 600 swaps on average and 13 000 at most
	// over a thousand seeds; a draw that runs out is drawn again.
	maxCoverSwaps = 1 << 16
	// coverUphill: one swap in coverUphill that leaves at most one more
	// shift unpaired is kept all the same, so that the search leaves a
	// local optimum (integers only: both sides must reach the same orders).
	coverUphill = 64
)

// ExpandPaired returns the ports of a paired predict stage (Stage.Pair): the
// span ports anchor+step·1 … anchor+step·span — where the peer's sequential
// NAT allocates the mappings of the peer's own paired stage, wrapping
// inside [1024, 65535] as a sequential allocator does — in the side's pair
// order (pairOrders; the responder's when in.Responder). A position whose
// port is filtered (sensitive, below 1024 and not allowed, or already sent
// to the IP) is sent to a substitute port beyond the window instead: its
// pairs are lost, but the side's own NAT still moves by one, so the
// positions after it stay aligned. Substitutes start two steps past the
// window and lie two steps apart, so that none is next to another port of
// the stage: neither order has a run of three positions, so for any step a
// NAT allocates by (|step| ≤ 16 is plenty) the result has no run of three
// consecutive ports either, and the send gate's run guard (two for
// initiated packets) never holds a paired packet back. Only a
// larger odd step over a long window can bring distant positions next to
// each other modulo the range; should that make a run of four, the ports
// are reordered as any other stage's (limitConsecutive).
func ExpandPaired(anchor uint16, steps []int16, span int, in ExpandInput) []uint16 {
	if span <= 0 || anchor == 0 {
		return nil
	}
	step := 1
	if len(steps) > 0 && steps[0] != 0 {
		step = int(steps[0])
	}
	pi, tau := pairOrders(in.PairSeed, span)
	order := pi
	if in.Responder {
		order = tau
	}
	avoid := in.avoid()
	window := make(map[uint16]bool, span)
	for k := 1; k <= span; k++ {
		window[wrapPort(int(anchor)+step*k)] = true
	}
	used := make(map[uint16]bool, span)
	next := span + 2 // the next substitute position
	out := make([]uint16, 0, span)
	for _, pos := range order {
		v := wrapPort(int(anchor) + step*(pos+1))
		if avoid(v) || used[v] {
			// A substitute is never a port of the window, so both sides pick
			// the same substitutes whatever their order.
			v = 0
			for ; next <= span+maxSubstitutes; next++ {
				if w := wrapPort(int(anchor) + step*next); !avoid(w) && !window[w] && !used[w] {
					v = w
					next += 2
					break
				}
			}
			if v == 0 {
				continue
			}
		}
		used[v] = true
		out = append(out, v)
	}
	if MaxConsecutiveRun(out) > 3 {
		out = limitConsecutive(substream(in.PairSeed, "pair-fix", 0), out)
	}
	return out
}

// wrapPort folds a port computed past either end into [1024, 65535], the
// range a sequential allocator wraps around in.
func wrapPort(v int) uint16 {
	return uint16(minUserPort + ((v-minUserPort)%portRange+portRange)%portRange)
}

// pairOrders returns the two send orders of a paired predict stage over n
// window positions, drawn from the pair seed alike on both sides: the
// initiator's j-th packet goes to the responder's position pi[j], the
// responder's i-th to the initiator's position tau[i]. A position is a
// side's predict mapping in allocation order, as its peer predicted it.
//
// When both predictions are exact, the initiator's j-th mapping targets the
// responder's mapping pi[j], which targets it back when tau[pi[j]] = j: that
// pair needs only one of its two packets to arrive after the other's mapping
// exists. A side's NAT may run ahead of the prediction — another host's
// mapping, a lost probe the anchor missed — by dI and dR positions; the pair
// j then needs tau[pi[j]−dR] = j+dI. tau reserves max(n/8, 4) exact pairs
// (dI = dR = 0) and one pair for every other shift with dI, dR ≤ 5 as room
// allows. In a window of at least 16 positions every shift up to 4 must get
// its pair (the others' noise moves an allocator by two to four
// ports between an anchor refresh and the fire): where the reservation
// leaves one out, a local search swaps positions of either order until all
// 25 are paired (coverShifts), or the draw is repeated. Neither order has a
// run of three consecutive positions. Both are a pure function of the seed:
// each side derives them on its own (both from the initiator's spray seed).
func pairOrders(seed [8]byte, n int) (pi, tau []int) {
	r := substream(seed, "pair", 0)
	for range maxPairTries {
		if pi = randomOrder(r, n); pi == nil {
			continue
		}
		if tau = constrainedOrder(r, pi); tau == nil {
			continue
		}
		if n < minPairSpan || coverShifts(r, pi, tau) {
			return pi, tau
		}
	}
	// Out of reach in practice (a draw fails with probability below 0.6):
	// swapped neighbours, 1 0 3 2 …, are their own inverse and pair exactly.
	pi = make([]int, n)
	for i := range pi {
		pi[i] = i ^ 1
		if pi[i] >= n {
			pi[i] = i
		}
	}
	return pi, slices.Clone(pi)
}

// randomOrder is a uniformly drawn permutation of n positions without a run
// of three consecutive positions, or nil after a draw with one.
func randomOrder(r *rand.ChaCha8, n int) []int {
	p := make([]int, n)
	for i := range p {
		p[i] = i
	}
	shuffleInts(r, p)
	if permRun(p) > 2 {
		return nil
	}
	return p
}

// constrainedOrder builds the responder's order for the initiator's order
// pi (see pairOrders), or returns nil when the draw found no room for the
// exact pairs, or — in a window shorter than minPairSpan, which no local
// search follows — left a run of three.
func constrainedOrder(r *rand.ChaCha8, pi []int) []int {
	n := len(pi)
	tau := make([]int, n)
	for i := range tau {
		tau[i] = -1
	}
	taken := make([]bool, n) // initiator positions some tau entry already targets
	js := make([]int, n)
	for i := range js {
		js[i] = i
	}
	// reserve fixes quota pairs for the shift (dI, dR), at initiator
	// packets in a random order, and reports whether it found them all.
	reserve := func(dI, dR, quota int) bool {
		shuffleInts(r, js)
		for _, j := range js {
			if quota == 0 {
				break
			}
			x, y := pi[j]-dR, j+dI
			if x >= 0 && x < n && y < n && tau[x] < 0 && !taken[y] {
				tau[x], taken[y] = y, true
				quota--
			}
		}
		return quota == 0
	}
	if !reserve(0, 0, max(n/8, min(n, minExactPair))) {
		return nil
	}
	for d := 1; d <= maxPairShift; d++ {
		// The shifts whose larger part is d: (d, 0…d) and (0…d−1, d).
		for e := 0; e <= d; e++ {
			reserve(d, e, 1)
			if e != d {
				reserve(e, d, 1)
			}
		}
	}
	var free []int
	for y, t := range taken {
		if !t {
			free = append(free, y)
		}
	}
	shuffleInts(r, free)
	for x := range tau {
		if tau[x] < 0 {
			tau[x], free = free[0], free[1:]
		}
	}
	if n < minPairSpan && permRun(tau) > 2 {
		return nil
	}
	return tau
}

// coverShifts completes the draw (pi, tau) of a window of at least
// minPairSpan positions in place, swapping two positions of one order at a
// time, until every shift up to minPairShift has a pair, the exact pairs
// number max(n/8, 4) again and neither order has a run of three
// (coverDefect is 0). A swap that adds no defect is kept; one that adds one
// unpaired shift is kept once in coverUphill draws; anything else is undone.
// It reports false when maxCoverSwaps run out first.
func coverShifts(r *rand.ChaCha8, pi, tau []int) bool {
	n := len(pi)
	exact := max(n/8, min(n, minExactPair))
	rho := make([]int, n)
	defect := coverDefect(pi, tau, rho, exact)
	for range maxCoverSwaps {
		if defect == 0 {
			return true
		}
		p := pi
		if r.Uint64()&1 == 0 {
			p = tau
		}
		a, b := int(r.Uint64()%uint64(n)), int(r.Uint64()%uint64(n))
		p[a], p[b] = p[b], p[a]
		d := coverDefect(pi, tau, rho, exact)
		if d <= defect || d <= defect+1 && r.Uint64()%coverUphill == 0 {
			defect = d
			continue
		}
		p[a], p[b] = p[b], p[a]
	}
	return defect == 0
}

// coverDefect counts what keeps (pi, tau) from a complete pairing: the
// shifts (dI, dR) up to minPairShift without a pair, the exact pairs
// missing below exact, and a run of three in either order (each of the
// last two counts as many as are needed to fix it, at least one). rho is
// scratch space of len(pi).
func coverDefect(pi, tau, rho []int, exact int) int {
	n := len(pi)
	for j, x := range pi {
		rho[x] = j // the initiator packet that targets responder position x
	}
	var paired [minPairShift + 1][minPairShift + 1]int
	for x, y := range tau {
		// The responder's x-th mapping lands at position x+dR and is the one
		// the initiator's packet rho[x+dR] targets; it targets back the
		// initiator position y, which is that packet's mapping when the
		// initiator ran dI = y − rho[x+dR] ahead.
		for dR := 0; dR <= minPairShift && x+dR < n; dR++ {
			if dI := y - rho[x+dR]; dI >= 0 && dI <= minPairShift {
				paired[dI][dR]++
			}
		}
	}
	defect := 0
	for dI := range paired {
		for dR := range paired[dI] {
			if paired[dI][dR] == 0 {
				defect++
			}
		}
	}
	defect += max(exact-paired[0][0], 0)
	if permRun(pi) > 2 {
		defect++
	}
	if permRun(tau) > 2 {
		defect++
	}
	return defect
}

// permRun is the longest run of consecutive positions in an order.
func permRun(p []int) int {
	best, run := min(len(p), 1), 1
	for i := 1; i < len(p); i++ {
		d := p[i] - p[i-1]
		switch {
		case d != 1 && d != -1:
			run = 1
		case run >= 2 && p[i-1]-p[i-2] == d:
			run++
		default:
			run = 2
		}
		best = max(best, run)
	}
	return best
}

// shuffleInts applies a Fisher-Yates permutation driven by r, in place.
func shuffleInts(r *rand.ChaCha8, s []int) {
	for i := len(s) - 1; i > 0; i-- {
		j := int(r.Uint64() % uint64(i+1))
		s[i], s[j] = s[j], s[i]
	}
}
