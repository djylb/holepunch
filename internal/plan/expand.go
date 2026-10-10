package plan

import (
	"math/rand/v2"
	"net/netip"
	"slices"
	"time"

	"github.com/djylb/holepunch/protocol"
)

// This file is the client face: it turns one protocol.Stage plus the 8-byte
// spray seed into the concrete, ordered target sequence the sender emits.
// Everything here is a pure function of (seed, stage): both peers reproduce the
// same sequence, and the returned port order never has a run of more than three
// consecutive ports.

// ExpandInput carries the per-session state an expansion needs beyond the
// stage itself.
type ExpandInput struct {
	// Seed is udpwire.SpraySeed(token, route, role, round, RoundPlan.Seed).
	Seed [8]byte
	// StageIndex identifies the stage within the round (0-based); it selects an
	// independent sub-stream so two stages with the same parameters still get
	// different orders.
	StageIndex int
	// Allow lists ports exempt from the sensitive / sub-1024 filter (the peer's
	// observed mappings). May be nil.
	Allow map[uint16]struct{}
	// Exclude reports ports already sent to this IP this session; such ports
	// are dropped. May be nil.
	Exclude func(uint16) bool
	// PairSeed orders a paired predict stage (Stage.Pair, ExpandPaired): the
	// initiator's spray seed of the round, udpwire.SpraySeed(token, route,
	// initiator, round, RoundPlan.Seed), on both sides. Responder selects the
	// responder's order.
	PairSeed  [8]byte
	Responder bool
}

func (in ExpandInput) avoid() func(uint16) bool {
	return func(p uint16) bool {
		if avoidPort(p, in.Allow) {
			return true
		}
		return in.Exclude != nil && in.Exclude(p)
	}
}

// ExpandStage returns the ordered destination targets of st. direct stages
// return their (already concrete) targets verbatim; predict and random stages
// are generated from the seed — a paired predict stage from the pair seed
// (ExpandPaired); a fresh_peer stage aims at the peer's fresh ports, drawn
// from the pair seed (FreshPorts); reply_only and fresh return nil —
// a fresh stage's destinations belong to its sockets. A birthday round is a
// random stage with sockets > 1 on the wire, so it flows through the random
// path.
func ExpandStage(st protocol.Stage, in ExpandInput) []netip.AddrPort {
	switch st.Kind {
	case protocol.StageDirect:
		return append([]netip.AddrPort(nil), st.Targets...)
	case protocol.StagePredict:
		if st.Pair {
			return addrs(st.IP, ExpandPaired(st.Anchor, st.Steps, int(st.Span), in))
		}
		return addrs(st.IP, ExpandPredict(st.Anchor, st.Steps, int(st.Span), in))
	case protocol.StageRandom:
		return addrs(st.IP, ExpandRandom(st.Lo, st.Hi, int(st.Count), in))
	case protocol.StageFreshPeer:
		return addrs(st.IP, FreshPorts(in.PairSeed, int(st.Count)))
	default:
		return nil
	}
}

// ExpandPredict returns the predicted ports, scattered deterministically and
// with no run of more than three consecutive ports. It returns at most
// span ports and skips sensitive, sub-1024 and
// already-sent ports.
func ExpandPredict(anchor uint16, steps []int16, span int, in ExpandInput) []uint16 {
	if span <= 0 {
		return nil
	}
	vals := predictPortValues(anchor, steps, span, in.avoid())
	r := substream(in.Seed, "predict", in.StageIndex)
	shuffleU16(r, vals)
	return limitConsecutive(r, vals)
}

// ExpandRandom returns count deterministic random ports in [lo, hi] (defaulting
// to [1024, 65535]), skipping sensitive, sub-1024 and already-sent ports, with
// no run of more than three consecutive ports.
func ExpandRandom(lo, hi uint16, count int, in ExpandInput) []uint16 {
	if count <= 0 {
		return nil
	}
	r := substream(in.Seed, "random", in.StageIndex)
	vals := randomPortValues(r, lo, hi, count, in.avoid())
	return limitConsecutive(r, vals)
}

// ScatterPorts returns ports in an order drawn from the spray seed, with no run
// of more than three consecutive ports: the order in which a client sends the
// ports of a peer_targets window. In Lo..Hi order a window would leave as the
// same maximal run in every session; scattered, its order differs per session,
// round and role, as every generated port sequence must. index selects an
// independent sub-stream, so two windows of one round are scattered
// differently. ports is not modified.
func ScatterPorts(seed [8]byte, index int, ports []uint16) []uint16 {
	out := slices.Clone(ports)
	r := substream(seed, "window", index)
	shuffleU16(r, out)
	return limitConsecutive(r, out)
}

// RangeCapacity returns how many distinct, non-filtered ports a random stage
// can actually emit in [lo, hi] (lo defaults to 1024, hi to 65535). The
// planner caps a random grant to this so the grant equals the emittable count
// even for a pool smaller than the ladder value. allow
// exempts observed peer mappings from the filter.
//
// The range never reaches below 1024, so only the few sensitive ports above
// it can be missing: the count is the range's width less those of them it
// contains and allow does not exempt — constant time instead of a walk over
// up to 64 512 ports on every Round.
func RangeCapacity(lo, hi uint16, allow map[uint16]struct{}) int {
	if lo < minUserPort {
		lo = minUserPort
	}
	if hi == 0 || hi < lo {
		hi = 65535
	}
	n := int(hi) - int(lo) + 1
	for _, p := range sensitiveUserPorts() {
		if _, ok := allow[p]; !ok && p >= lo && p <= hi {
			n--
		}
	}
	return n
}

// DirectOffsets returns the send offsets (from stage fire) of the repeats of a
// single Direct target: gap_i = 30 ms + u_i*min(20*i^2, 250) ms, u_i in
// [0.5, 1] derived from the spray seed by (stage, target, i). offsets[0] is
// always 0 and the sequence is strictly
// increasing.
func DirectOffsets(seed [8]byte, stageIndex, targetIndex, repeats int) []time.Duration {
	if repeats <= 0 {
		return nil
	}
	out := make([]time.Duration, repeats)
	var cum time.Duration
	for i := 1; i < repeats; i++ {
		u := unitFloat(substream(seed, "direct", stageIndex, targetIndex, i))
		spread := min(20*i*i, 250)
		gapMs := 30.0 + u*float64(spread)
		cum += time.Duration(gapMs * float64(time.Millisecond))
		out[i] = cum
	}
	return out
}

// MaxConsecutiveRun returns the length (in ports) of the longest run whose
// adjacent ports all differ by the same +1 or -1. It is the quantity the <= 3
// constraint bounds.
func MaxConsecutiveRun(ports []uint16) int {
	if len(ports) == 0 {
		return 0
	}
	best, run := 1, 1
	for i := 1; i < len(ports); i++ {
		d := int(ports[i]) - int(ports[i-1])
		switch {
		case d != 1 && d != -1:
			run = 1
		case run >= 2 && int(ports[i-1])-int(ports[i-2]) == d:
			run++
		default:
			run = 2
		}
		if run > best {
			best = run
		}
	}
	return best
}

// ---- internals ----

func addrs(ip netip.Addr, ports []uint16) []netip.AddrPort {
	if !ip.IsValid() || len(ports) == 0 {
		return nil
	}
	out := make([]netip.AddrPort, 0, len(ports))
	for _, p := range ports {
		out = append(out, netip.AddrPortFrom(ip, p))
	}
	return out
}

func predictPortValues(anchor uint16, steps []int16, span int, avoid func(uint16) bool) []uint16 {
	if span <= 0 || anchor == 0 {
		return nil
	}
	out := make([]uint16, 0, span)
	seen := make(map[uint16]struct{}, span)
	// A sequential allocator wraps around inside [1024, 65535], so the window
	// does too: a downward allocator near 1024 continues at 65535.
	add := func(v int) {
		if len(out) >= span {
			return
		}
		p := wrapPort(v)
		if _, ok := seen[p]; ok {
			return
		}
		seen[p] = struct{}{}
		if avoid != nil && avoid(p) {
			return
		}
		out = append(out, p)
	}
	ss := make([]int, 0, len(steps))
	for _, s := range steps {
		if s != 0 {
			ss = append(ss, int(s))
		}
	}
	if len(ss) == 0 {
		ss = []int{1}
	}
	a := int(anchor)
	// likely-next neighbourhood: anchor+step, anchor+2*step and their +-1.
	for _, s := range ss {
		if len(out) >= span {
			break
		}
		for _, m := range []int{1, 2} {
			add(a + m*s)
			add(a + m*s - 1)
			add(a + m*s + 1)
		}
	}
	// outward interval sweep until span is filled or the range is exhausted.
	maxStep := 1
	for _, s := range ss {
		if v := abs(s); v > maxStep {
			maxStep = v
		}
	}
	for k := 1; len(out) < span; k++ {
		for _, s := range ss {
			add(a + k*s)
			add(a - k*s)
		}
		if 2*k*maxStep >= portRange {
			break // both directions met: every port of the range was tried
		}
	}
	return out
}

func randomPortValues(r *rand.ChaCha8, lo, hi uint16, count int, avoid func(uint16) bool) []uint16 {
	if count <= 0 {
		return nil
	}
	if lo < minUserPort {
		lo = minUserPort
	}
	if hi == 0 || hi < lo {
		hi = 65535
	}
	span := int(hi) - int(lo) + 1
	if count > span {
		count = span
	}
	seen := make(map[uint16]struct{}, count)
	out := make([]uint16, 0, count)
	for attempts := 0; len(out) < count && attempts < count*32+span*2; attempts++ {
		p := uniformU16(r, lo, hi)
		if _, ok := seen[p]; ok {
			continue
		}
		seen[p] = struct{}{}
		if avoid != nil && avoid(p) {
			continue
		}
		out = append(out, p)
	}
	return out
}

// limitConsecutive reorders ports so that no run of same-direction +-1 steps
// exceeds three (a hard constraint). It is driven by
// a seeded shuffle, so the order varies per session, then a greedy placement
// that never appends a port extending the trailing run past three; in the one
// case a forced element would, it is inserted at the earliest safe slot
// instead. The result is guaranteed: a run of four needs the unique continuing
// value, which the insertion avoids.
func limitConsecutive(r *rand.ChaCha8, ports []uint16) []uint16 {
	if len(ports) <= 3 {
		return ports // at most three elements can only form a run of <= 3
	}
	pool := append([]uint16(nil), ports...)
	shuffleU16(r, pool)
	out := make([]uint16, 0, len(pool))
	used := make([]bool, len(pool))
	placed := 0
	for placed < len(pool) {
		pick := -1
		for i := range pool {
			if used[i] {
				continue
			}
			if !wouldExtendRun(out, pool[i]) {
				pick = i
				break
			}
		}
		if pick >= 0 {
			used[pick] = true
			out = append(out, pool[pick])
			placed++
			continue
		}
		// Every remaining port would extend the trailing run; this can happen
		// only for a single remaining port equal to the run's continuing value.
		// Insert it at the earliest slot that keeps every local run <= 3.
		for i := range pool {
			if used[i] {
				continue
			}
			used[i] = true
			out = insertSafe(out, pool[i])
			placed++
		}
	}
	return out
}

// trailingRun returns the length and direction (+1/-1) of the run of
// same-direction +-1 steps at the end of out.
func trailingRun(out []uint16) (length, dir int) {
	n := len(out)
	if n == 0 {
		return 0, 0
	}
	if n == 1 {
		return 1, 0
	}
	d := int(out[n-1]) - int(out[n-2])
	if d != 1 && d != -1 {
		return 1, 0
	}
	length = 2
	for i := n - 2; i > 0; i-- {
		if int(out[i])-int(out[i-1]) == d {
			length++
		} else {
			break
		}
	}
	return length, d
}

// wouldExtendRun reports whether appending p to out would make the trailing
// run four ports long.
func wouldExtendRun(out []uint16, p uint16) bool {
	length, dir := trailingRun(out)
	if length < 3 || dir == 0 {
		return false
	}
	return int(p)-int(out[len(out)-1]) == dir
}

// insertSafe inserts p into out at the earliest index that keeps every run at
// that seam <= 3, falling back to append.
func insertSafe(out []uint16, p uint16) []uint16 {
	for j := 0; j <= len(out); j++ {
		cand := make([]uint16, 0, len(out)+1)
		cand = append(cand, out[:j]...)
		cand = append(cand, p)
		cand = append(cand, out[j:]...)
		if MaxConsecutiveRun(cand) <= 3 {
			return cand
		}
	}
	return append(out, p)
}

func abs(v int) int {
	if v < 0 {
		return -v
	}
	return v
}
