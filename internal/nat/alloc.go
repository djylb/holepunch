package nat

import (
	"cmp"
	"net/netip"
	"slices"
	"time"

	"github.com/djylb/holepunch/protocol"
)

// Port allocation thresholds.
const (
	maxStep        = 64   // largest |d*| of a sequential allocator
	stepShare      = 0.75 // share of same-socket differences equal to d*
	maxPoolSpan    = 4096 // largest span of a port block estimate
	minAllocSample = 3    // any random claim
	minPoolSample  = 4    // any pool claim
	randomMediumN  = 5    // random at Medium
	poolMediumN    = 6    // pool at Medium, random at High: 6 uniform ports fall in 4096 with p < 1e-5
	// minVelocityBase is the shortest baseline a velocity is measured over:
	// across the round trip between the primary socket's and the second
	// socket's probes. Over a shorter one a single foreign mapping reads as
	// tens of ports a second.
	minVelocityBase = 100 * time.Millisecond
	// portRange is the width of the range a sequential allocator wraps
	// around in, 1024–65535: a step from 65535 to 1024 is one step.
	portRange = 65536 - 1024
)

// allocSample is one mapping of an allocation sequence: the row it came
// from and its send index, the position of the probe that created it among
// the sends that created mappings — consecutive samples k sends apart are k
// allocations apart. send < 0 is unknown.
type allocSample struct {
	Row
	send int
}

// classifyAllocationLocked classifies an APDM allocator from the primary
// socket's samples and the second socket's. On an APDM NAT every
// probe point of a socket is a new mapping, answered or not, so a
// sample's send index is its point's rank among the socket's points
// (sendIndexedLocked). The velocity spans the round trip between the two
// sockets (probeVelocity).
//
// A socket whose first mapping kept its local port while its later ones moved
// is evidence of a fresh-socket-preserving allocator: both sockets make it
// AllocPreserveFresh at High confidence, one at Medium. A sequential allocator
// stays Sequential: its prediction covers every mapping, not only a socket's
// first.
func (t *ObsTable) classifyAllocationLocked(tr *protocol.Traits, samples []sample, p SocketMeta, scope Scope) {
	seq0 := t.sendIndexedLocked(p.ID, rowsOf(samples), scope)
	var seq1 []allocSample
	fresh := 0
	if preservedFresh(seq0, p.Local) {
		fresh++
	}
	if s, ok := t.socketOfKindLocked(protocol.SocketSecond); ok {
		seq1 = t.sendIndexedLocked(s.ID, rowsOf(t.firstValuesLocked(s.ID, scope)), scope)
		if preservedFresh(seq1, s.Local) {
			fresh++
		}
	}
	classifyPorts(tr, seq0, seq1)
	if tr.PortAlloc == protocol.AllocSequential {
		tr.PortNoisy = foreignSteps(int(tr.PortStep), seq0) || foreignSteps(int(tr.PortStep), seq1)
	}
	if tr.PortAlloc == protocol.AllocSequential && len(seq0) > 0 && len(seq1) > 0 {
		last, next := seq0[len(seq0)-1].Row, seq1[0].Row
		own := t.pointsBetweenLocked(last.FirstSeq, next.FirstSeq, scope)
		tr.PortVelocity = probeVelocity(int(tr.PortStep), last, next, own)
		// Over the gap between the sockets, however short, a port beyond
		// this side's own steps is another host's.
		tr.PortNoisy = tr.PortNoisy || portDelta(last.Observed.Port(), next.Observed.Port()) != own*int(tr.PortStep)
	}
	tr.FirstPreserved = samples[0].Observed.Port() == p.Local.Port()
	if fresh > 0 && tr.PortAlloc != protocol.AllocSequential {
		tr.PortAlloc, tr.PortAllocConf = protocol.AllocPreserveFresh, confIf(fresh == 2, protocol.ConfHigh, protocol.ConfMedium)
		tr.PortRangeLo, tr.PortRangeHi = 0, 0
	}
}

// preservedFresh reports whether a socket's mappings, in creation order,
// show a fresh socket keeping its local port: the first — made by the
// socket's first probe — has the local port, and a later one has another.
func preservedFresh(seq []allocSample, local netip.AddrPort) bool {
	return len(seq) >= 2 && local.Port() != 0 && seq[0].send <= 0 && seq[0].Observed.Port() == local.Port() &&
		slices.ContainsFunc(seq[1:], func(s allocSample) bool { return s.Observed.Port() != local.Port() })
}

// sendIndexedLocked pairs the rows of socket sock, in send order, with their
// send index: the rank of their point among the socket's probe points that
// crossed the NAT, in first-send order. The points include the unanswered ones
// — on the client a probe that got no answer, on the server a reported row
// whose probes never arrived (natprobe's merge keeps them) — because the lost
// probe made its mapping on the way out. The seq alone would not do: every
// socket and family of the session draws from one counter.
func (t *ObsTable) sendIndexedLocked(sock uint8, rows []Row, scope Scope) []allocSample {
	points := t.crossingPointsLocked(scope, func(k PointKey) bool { return k.Socket == sock })
	out := make([]allocSample, len(rows))
	for i, r := range rows {
		out[i] = allocSample{Row: r, send: slices.IndexFunc(points, func(p Row) bool { return p.Key == r.Key })}
	}
	return out
}

// pointsBetweenLocked counts the probe points of the family, on any
// socket, whose first send came after seq a and no later than seq b: the
// mappings this host created in between, answered or not.
func (t *ObsTable) pointsBetweenLocked(a, b uint32, scope Scope) int {
	n := 0
	for _, p := range t.crossingPointsLocked(scope, func(PointKey) bool { return true }) {
		if p.FirstSeq > a && p.FirstSeq <= b {
			n++
		}
	}
	return n
}

// crossingPointsLocked returns one row per server probe point (main or alt
// group) that keep selects and whose packets crossed the NAT — its
// observer is in the classification scope, or unknown to the table — in
// first-send order; only the key and the first seq of a row are meant.
func (t *ObsTable) crossingPointsLocked(scope Scope, keep func(PointKey) bool) []Row {
	var out []Row
	for _, r := range t.rows {
		if r.Key.Source != SourceServer && r.Key.Source != SourceServerAlt || !keep(r.Key) {
			continue
		}
		if o := t.observerLocked(r.Key.Observer); o != nil && o.Scope != scope {
			continue
		}
		if i := slices.IndexFunc(out, func(p Row) bool { return p.Key == r.Key }); i >= 0 {
			out[i].FirstSeq = min(out[i].FirstSeq, r.FirstSeq)
			continue
		}
		out = append(out, r)
	}
	slices.SortStableFunc(out, func(a, b Row) int { return cmp.Compare(a.FirstSeq, b.FirstSeq) })
	return out
}

// perIPMappingsLocked returns the primary socket's mappings toward distinct
// server IPs, in creation order: the first sample of each main group and the
// alt group's solicited answers. An ADM NAT creates one mapping per
// destination IP, so this is the sequence its allocator produced, one
// allocation apart. A single-IP deployment has at most two such mappings,
// too few to classify.
func (t *ObsTable) perIPMappingsLocked(sock uint8, samples []sample, scope Scope) []allocSample {
	var rows []Row
	var groups []uint8
	for _, s := range samples {
		if !slices.Contains(groups, s.group) {
			groups = append(groups, s.group)
			rows = append(rows, s.Row)
		}
	}
	for _, o := range t.observers {
		if !o.Alt || o.Scope != scope {
			continue
		}
		if r, ok := t.firstValueLocked(PointKey{Socket: sock, Source: SourceServerAlt, Observer: o.ID}); ok {
			rows = append(rows, r)
		}
	}
	slices.SortStableFunc(rows, func(a, b Row) int { return cmp.Compare(a.FirstSeq, b.FirstSeq) })
	out := make([]allocSample, len(rows))
	for i, r := range rows {
		out[i] = allocSample{Row: r, send: i}
	}
	return out
}

// classifyPorts classifies the allocation behind two mapping sequences in
// creation order: seq0 created back to back (the primary socket) and seq1,
// optional, at least one RTT later (the second socket).
//
// The step only uses differences within one sequence: between the two, other
// hosts behind the same NAT allocate ports too, so a mixed difference list
// would turn a busy sequential CGNAT into "random". A difference over
// k sends counts as k steps — a probe lost on the way still took its port —
// and one across the end of the range as the step it is (stepDiffs). Random
// ports within a small span estimate a port block.
func classifyPorts(tr *protocol.Traits, seq0, seq1 []allocSample) {
	intra := append(stepDiffs(seq0), stepDiffs(seq1)...)
	all := slices.Concat(seq0, seq1)
	n := len(all)
	if d, ok := dominantStep(intra); ok {
		tr.PortAlloc, tr.PortStep = protocol.AllocSequential, int16(d)
		tr.PortAllocConf = confIf(len(intra) >= 3, protocol.ConfHigh, protocol.ConfMedium)
		latest := slices.MaxFunc(all, func(a, b allocSample) int { return cmp.Compare(a.FirstSeq, b.FirstSeq) })
		tr.PortAnchor = latest.Observed.Port()
		return
	}
	if lo, hi, ok := blockEstimate(ports(all)); ok {
		tr.PortAlloc, tr.PortRangeLo, tr.PortRangeHi = protocol.AllocPool, lo, hi
		tr.PortAllocConf = confIf(n >= poolMediumN, protocol.ConfMedium, protocol.ConfLow)
		return
	}
	if n >= minAllocSample {
		tr.PortAlloc = protocol.AllocRandom
		switch {
		case n >= poolMediumN:
			tr.PortAllocConf = protocol.ConfHigh
		case n >= randomMediumN:
			tr.PortAllocConf = protocol.ConfMedium
		default:
			tr.PortAllocConf = protocol.ConfLow
		}
	}
}

// stepDiffs returns the port differences of consecutive samples, each per
// send: a difference over k sends that k divides is divided by k, as a
// sequential allocator moved k steps; any other is kept whole, for
// dominantStep to read as a multiple of the step or not.
func stepDiffs(seq []allocSample) []int {
	var out []int
	for i := 1; i < len(seq); i++ {
		a, b := seq[i-1], seq[i]
		d := portDelta(a.Observed.Port(), b.Observed.Port())
		if k := b.send - a.send; a.send >= 0 && b.send >= 0 && k > 1 && d%k == 0 {
			d /= k
		}
		out = append(out, d)
	}
	return out
}

// probeVelocity is the allocation velocity of other hosts from the gap
// between the primary socket's last sample and the second socket's first:
// the port difference less own steps — one per point this host probed in
// between, the second socket's first included (own) — over the time
// between the two first sends. A baseline shorter than minVelocityBase, an
// unknown send time, or others moving against the step give no velocity.
func probeVelocity(step int, last, next Row, own int) float32 {
	dt := next.FirstSent - last.FirstSent
	if last.FirstSent < 0 || next.FirstSent < 0 || dt < minVelocityBase {
		return 0
	}
	others := portDelta(last.Observed.Port(), next.Observed.Port()) - own*step
	if sign(others) != sign(step) {
		return 0
	}
	return float32(float64(others) / dt.Seconds())
}

// foreignSteps reports whether a socket's consecutive mappings moved by
// more than its own sends' steps: another host took the ports in between.
func foreignSteps(step int, seq []allocSample) bool {
	for i := 1; i < len(seq); i++ {
		a, b := seq[i-1], seq[i]
		k := 1
		if a.send >= 0 && b.send > a.send {
			k = b.send - a.send
		}
		if portDelta(a.Observed.Port(), b.Observed.Port()) != k*step {
			return true
		}
	}
	return false
}

// portDelta is b − a along the wrapping port range: the short way round.
func portDelta(a, b uint16) int {
	d := int(b) - int(a)
	switch {
	case d > portRange/2:
		d -= portRange
	case d < -portRange/2:
		d += portRange
	}
	return d
}

// dominantStep returns d* when there are at least two differences, d* is
// their mode (ties: smaller |d|, then positive), 1 ≤ |d*| ≤ 64, at least 75%
// of the differences equal d*, and the others are positive multiples of it
// (a mapping created by someone else in between).
func dominantStep(ds []int) (int, bool) {
	if len(ds) < 2 {
		return 0, false
	}
	best, bestN := 0, 0
	for _, d := range ds {
		n := 0
		for _, e := range ds {
			if e == d {
				n++
			}
		}
		if n > bestN || (n == bestN && (abs(d) < abs(best) || (abs(d) == abs(best) && d > best))) {
			best, bestN = d, n
		}
	}
	if best == 0 || abs(best) > maxStep || float64(bestN) < stepShare*float64(len(ds)) {
		return 0, false
	}
	for _, d := range ds {
		if d != best && (d%best != 0 || d/best < 1) {
			return 0, false
		}
	}
	return best, true
}

// blockEstimate estimates a port block from n ≥ 4 ports spanning ≤ 4096:
// B̂ = 2^ceil(log2(span·(n+1)/(n−1))) and Lo = the smallest port aligned down
// to B̂; the block doubles until it holds every sample.
func blockEstimate(ps []uint16) (lo, hi uint16, ok bool) {
	n := len(ps)
	if n < minPoolSample {
		return 0, 0, false
	}
	mn, mx := slices.Min(ps), slices.Max(ps)
	span := int(mx) - int(mn)
	if span > maxPoolSpan {
		return 0, 0, false
	}
	est := float64(span) * float64(n+1) / float64(n-1)
	b := 1
	for float64(b) < est {
		b <<= 1
	}
	for {
		l := int(mn) &^ (b - 1)
		if l+b-1 >= int(mx) {
			return uint16(l), uint16(min(l+b-1, 65535)), true
		}
		b <<= 1
	}
}

func rowsOf(s []sample) []Row {
	out := make([]Row, len(s))
	for i := range s {
		out[i] = s[i].Row
	}
	return out
}

func ports(seq []allocSample) []uint16 {
	out := make([]uint16, len(seq))
	for i, r := range seq {
		out[i] = r.Observed.Port()
	}
	return out
}

func sign(v int) int { return cmp.Compare(v, 0) }

func abs(v int) int {
	if v < 0 {
		return -v
	}
	return v
}
