package plan

import (
	"cmp"
	"math"
	"net/netip"
	"slices"
	"time"

	"github.com/djylb/holepunch/protocol"
)

// prediction is where a sequential peer's next external port is expected
// when the round fires.
type prediction struct {
	anchor  uint16  // the peer's last allocated port extrapolated to FireAt; 0 = none
	steps   []int16 // the allocation step; the expansion adds it to the anchor
	minSpan int     // 2·(|v|·σ_t + |step|), at most the range: the window the timing error spreads over
}

// minVelocityBase is the shortest interval a punch-time sample is compared
// over: closer points mostly measure the peer's own back-to-back mappings.
const minVelocityBase = 100 * time.Millisecond

// predictPeer predicts the external port of role's next mapping toward ip
// at in.FireAt.
//
// The base is the probe's anchor: PortAnchor created at PortAnchorMs, with
// the allocation velocity PortVelocity of other hosts behind the same NAT. A
// mapping of role observed while punching (in.Mappings) later than the base
// replaces it, being newer, and the base and the latest sample re-estimate
// the velocity: the port gap minus the role's own allocations between them
// (one step per distinct sample), over the time between them. The anchor is
// then extrapolated to FireAt: anchor + velocity·(FireAt − anchor time); the
// stage expansion adds the step. σ_t, the timing error of that guess, is the
// coordinator's alignment margin D.
func predictPeer(in RoundInput, role int, tr protocol.Traits, ip netip.Addr) prediction {
	step := int(tr.PortStep)
	p := prediction{steps: []int16{tr.PortStep}}
	if step == 0 {
		step, p.steps = 1, []int16{1}
	}
	if r, ok := refreshFor(in, role, tr.Family, ip); ok {
		return refreshedPrediction(in, role, r, tr, step, p)
	}
	anchor := int(tr.PortAnchor)
	if anchor == 0 {
		anchor = int(tr.Observed.Port())
	}
	at := time.Duration(tr.PortAnchorMs) * time.Millisecond
	v := float64(tr.PortVelocity)

	var samples []MappingSample
	for _, s := range in.Mappings[role] {
		if s.Addr.Addr().Unmap() == ip.Unmap() && s.Addr.Port() != 0 && (at <= 0 || s.At > at) {
			samples = append(samples, s)
		}
	}
	if len(samples) > 0 {
		slices.SortStableFunc(samples, func(a, b MappingSample) int { return cmp.Compare(a.At, b.At) })
		baseAt, basePort, own := at, anchor, 0
		if at <= 0 || anchor == 0 {
			baseAt, basePort, samples = samples[0].At, int(samples[0].Addr.Port()), samples[1:]
		}
		var seen []uint16
		for _, s := range samples {
			if !slices.Contains(seen, s.Addr.Port()) {
				seen = append(seen, s.Addr.Port())
				own++
			}
		}
		if len(samples) > 0 {
			last := samples[len(samples)-1]
			if dt := last.At - baseAt; dt >= minVelocityBase {
				others := float64(portDelta(basePort, int(last.Addr.Port()))-step*own) / dt.Seconds()
				if (others > 0) != (step > 0) {
					others = 0 // nobody else allocated in between, or noise against the step
				}
				v = others
			}
			anchor, at = int(last.Addr.Port()), last.At
		} else {
			anchor, at = basePort, baseAt
		}
	}
	if anchor == 0 {
		return p
	}
	if in.FireAt > 0 && at > 0 && in.FireAt > at && v != 0 {
		// Only the move modulo the range counts (wrapPort folds it), and
		// taken modulo the range first, a rate however large converts to
		// the same integer on every platform.
		anchor += int(math.Mod(math.Round(v*(in.FireAt-at).Seconds()), portRange))
	}
	p.anchor = wrapPort(anchor)
	p.minSpan = windowSpan(2 * (math.Abs(v)*in.D.Seconds() + math.Abs(float64(step))))
	return p
}

// windowSpan is a predicted window's width w rounded up to whole ports, at
// most the port range: a wider window holds no further port, and a huge
// rate does not overflow the conversion.
func windowSpan(w float64) int {
	return int(math.Ceil(min(w, portRange)))
}

// refreshedPrediction is predictPeer after an anchor refresh: the
// refresh's newest mapping is the newest point of the allocator (newest),
// so the anchor is that mapping — past the refresh's own later mapping,
// when only the first probe came — extrapolated by the others' rate to
// the fire time, and the window spreads over the timing error and the
// rate's Poisson spread over that time.
func refreshedPrediction(in RoundInput, role int, r AnchorRefresh, tr protocol.Traits, step int, p prediction) prediction {
	lambda, _ := refreshRate(in, role, r, tr, step)
	port, at, _, after := r.newest()
	ahead := 0.0
	if in.FireAt > at {
		ahead = lambda * (in.FireAt - at).Seconds()
	}
	p.anchor = wrapPort(int(port) + step*(after+int(math.Round(ahead))))
	spread := lambda*in.D.Seconds() + math.Sqrt(ahead) + 1
	p.minSpan = windowSpan(2 * spread * math.Abs(float64(step)))
	return p
}

// refreshFor is role's anchor refresh of family fam on ip, if any.
func refreshFor(in RoundInput, role int, fam protocol.Family, ip netip.Addr) (AnchorRefresh, bool) {
	for _, r := range in.Refresh[role] {
		if r.Family == fam && r.on(ip) {
			return r, true
		}
	}
	return AnchorRefresh{}, false
}

// on reports whether the refresh has a probe and every probe it has is
// on ip.
func (r AnchorRefresh) on(ip netip.Addr) bool {
	at := func(a netip.AddrPort) bool { return !a.IsValid() || a.Addr().Unmap() == ip.Unmap() }
	return (r.First.IsValid() || r.Second.IsValid()) && at(r.First) && at(r.Second)
}

// newest is the newest point of the allocator a refresh saw: its second
// mapping, or its first when the second did not come. before and
// after count the side's own refresh mappings on either side of that
// point: a probe that did not come was lost on the way after its NAT had
// mapped it, so it still moved the allocator.
func (r AnchorRefresh) newest() (port uint16, at time.Duration, before, after int) {
	if r.Second.IsValid() {
		return r.Second.Port(), r.SecondAt, 1, 0
	}
	return r.First.Port(), r.FirstAt, 0, 1
}

// rate is the allocation rate of other hosts between a refresh's two
// mappings, in steps a second: the steps between them less the
// second one, over the time between them. A refresh missing a probe
// measures nothing.
func (r AnchorRefresh) rate(step int) (float64, bool) {
	if !r.First.IsValid() || !r.Second.IsValid() {
		return 0, false
	}
	return r.rateFrom(r.First.Port(), r.FirstAt, step, 0)
}

// rateFrom is the others' rate between an earlier point of the allocator —
// port from, allocated at fromAt — and the refresh's newest mapping, of
// which own were the side's own mappings in between: the steps between the
// two less own and the newest mapping itself, over the time between them.
// A newest mapping that is not ahead of the point by own steps at least
// along step — the counted mappings do not match the NAT — or a time too
// short to tell measures nothing.
func (r AnchorRefresh) rateFrom(from uint16, fromAt time.Duration, step, own int) (float64, bool) {
	port, at, _, _ := r.newest()
	dt := at - fromAt
	d := portDelta(int(from), int(port))
	if step == 0 || dt < minRefreshGap || d%step != 0 || d/step < own+1 {
		return 0, false
	}
	return float64(d/step-own-1) / dt.Seconds(), true
}

// refreshRate is the others' rate role's refresh r measures.
// The two refresh probes alone span about 60 ms, in which a rate of 20 a
// second shows as one port give or take one. So the baseline starts at
// the probe's anchor — PortAnchor of tr, role's traits, on the refresh's
// IP — and spans the whole time since probing: the side's own mappings in
// between are every earlier round's (FamilyRound.Mapped) and the
// refresh's own before its newest point. The two probes' own rate is left
// for when the anchor cannot serve: on another IP, or behind the newest
// point by fewer steps than the counted mappings.
func refreshRate(in RoundInput, role int, r AnchorRefresh, tr protocol.Traits, step int) (float64, bool) {
	at := time.Duration(tr.PortAnchorMs) * time.Millisecond
	_, newestAt, before, _ := r.newest()
	if tr.PortAnchor != 0 && at > 0 && at < newestAt && r.on(tr.Observed.Addr()) {
		own := mappedSince(in, r.Family, role, 0) + before
		if lambda, ok := r.rateFrom(tr.PortAnchor, at, step, own); ok {
			return lambda, true
		}
	}
	return r.rate(step)
}

// refreshDrift is how many steps the allocator is expected to move at
// rate lambda from the refresh's newest mapping until at, kept short of
// the mean by driftMargin: a window that starts too far on misses the
// peer's first mappings for good, one that starts short still meets them
// through the pair orders' offset pairs. The others' allocations
// are a Poisson count, two to four over the 80–150 ms from a refresh to
// the fire at 20 a second, so the margin keeps most of the spread on the
// side the offset pairs cover.
func refreshDrift(lambda float64, r AnchorRefresh, at time.Duration) int {
	_, newestAt, _, _ := r.newest()
	if at <= newestAt {
		return 0
	}
	return max(int(math.Round(lambda*(at-newestAt).Seconds()))-driftMargin, 0)
}

// Refresh limits: two refresh probes closer than minRefreshGap tell
// no rate; driftMargin is how many steps the expected drift is kept short.
const (
	minRefreshGap = 20 * time.Millisecond
	driftMargin   = 3
)

// refreshAfter is how stale a sequential side's anchor may grow before a
// round re-reads it: beyond it a quiet-looking NAT may have moved.
const refreshAfter = 500 * time.Millisecond

// RefreshWanted lists, by role, the families of dec in which the side's anchor
// is worth refreshing before the round fires: the side is SEQ with a sequential
// allocator in a verified family and the peer's side of the family aims a
// predict stage at it. A paired family (seq_x_seq, both sides sequential)
// refreshes both sides unconditionally: its pair orders need both anchors
// exact, and the probe phase watches the allocators for some 25 ms only, too
// short to see the others' noise in a third of the runs at 20 a second.
// Elsewhere — a SEQ side under an OPEN or PDF peer — a side refreshes only on
// noise evidence: a measured velocity of other hosts, or other hosts' ports
// between its probes however short the baseline (Traits.PortNoisy), or its
// newest observation, by now on the FireAt axis, older than 500 ms. The
// coordinator adds what only it knows: the registration, the probe budget, the
// time left for the wait and the round. RND, preserve_fresh and EIM sides never
// qualify: a fresh anchor does not help predict them. Nor does a family
// natprobe measured as one only the cheap rounds can open (SeqRndVerdict): a
// refresh does not change that verdict.
func RefreshWanted(in RoundInput, dec RoundDecision, now time.Duration) [2][]protocol.Family {
	var out [2][]protocol.Family
	for fi, fp := range in.Class.fams {
		if fp.Unverified || fp.CheapOnly {
			continue
		}
		var anchored, due [2]bool
		for role := range 2 {
			tr := familyTraits(in.Views[role], fp.Family)
			if CategoryOf(tr) != CatSEQ || tr.PortAlloc != protocol.AllocSequential || fi >= len(dec.Sides[1-role]) {
				continue
			}
			if !slices.ContainsFunc(dec.Sides[1-role][fi].Stages, func(st protocol.Stage) bool { return st.Kind == protocol.StagePredict }) {
				continue
			}
			anchored[role] = true
			// The velocity has the step's sign: a downward allocator's is negative.
			due[role] = tr.PortVelocity != 0 || tr.PortNoisy || now-lastObservation(in, role, tr) > refreshAfter
		}
		paired := pairedFamily(in, fp)
		for role := range 2 {
			if anchored[role] && (due[role] || paired) {
				out[role] = append(out[role], fp.Family)
			}
		}
	}
	return out
}

// lastObservation is the newest observation of role's allocator in the
// family of tr, on the FireAt axis: the probe's anchor or a later mapping
// seen while punching.
func lastObservation(in RoundInput, role int, tr protocol.Traits) time.Duration {
	last := time.Duration(tr.PortAnchorMs) * time.Millisecond
	for _, s := range in.Mappings[role] {
		if s.Addr.Addr().Is4() == (tr.Family == protocol.FamilyUDP4) {
			last = max(last, s.At)
		}
	}
	return last
}
