package coord

import (
	"net/netip"
	"slices"
	"time"

	"github.com/djylb/holepunch/internal/nat"
	"github.com/djylb/holepunch/internal/plan"
	"github.com/djylb/holepunch/protocol"
)

// Anchor refresh before a round. Other hosts behind a sequential NAT move its
// allocator while a session waits; only a new mapping shows where it is now. So
// before the go of a round whose plan aims at a SEQ side's next ports — always
// in a paired SEQ × SEQ family, on noise evidence or a stale observation
// elsewhere — the coordinator asks the side for a refresh: two new sockets,
// about 60 ms apart, each send one probe to one observer. natprobe hands both
// probes over like the sandwich's; the planner then plans the round again from
// the newest mapping, advanced by the others' rate since probing, and the go
// leaves with the pair orders fixed as before. The wait for a side's family
// ends with its second probe, or a bounded time after its first — the planner
// then anchors on the one that came — and in any case a bounded time after the
// request. A later round waits about one control round trip and 60 ms more.
// Round 1 asks along with the summaries, so the wait overlaps their round trip;
// the clients have bound their sockets for the summary's plan by then, so its
// go carries that plan again with only the predict stages re-aimed. NoRefresh
// asks for none.

// refreshState is an anchor refresh under way, and the round it is for.
type refreshState struct {
	pending bool // waiting for the probes
	ready   bool // done waiting: the session goroutine plans the round again
	k       int
	gen     uint64
	until   time.Duration // stop waiting: the latest bound still open (refreshWaitLocked)
	cap     time.Duration // stop waiting at the latest, whatever came
	want    [2][2]bool    // by side and family index
	got     [2][2][2]refreshProbe
	d       decision // the plan before the refresh, kept if nothing came
	p       Planner
	cin     ClassifyInput
	// asked are the refreshes of round k, which made two mappings each
	// (Mapped).
	asked [2][2]bool
}

// refreshProbe is one refresh probe as natprobe saw it: the new socket's
// mapping and when, on the FireAt axis.
type refreshProbe struct {
	addr netip.AddrPort
	at   time.Duration
}

// Refresh timing: the client spaces its two probes refreshGap
// apart. The coordinator waits for a side's family until its second probe
// came, or for refreshGap and one and a half of the side's UDP round trips
// (udpRTTLocked) after its first: the second left refreshGap after the
// first, and the two travel the same path, differing by its jitter. A side
// none of whose probes come is waited for refreshGap, a control one-way
// plus a UDP one-way (at most the larger round trip) and refreshSlack
// after the request, never longer than maxRefreshWait.
const (
	refreshGap     = 60 * time.Millisecond
	refreshSlack   = 150 * time.Millisecond
	maxRefreshWait = 800 * time.Millisecond
	refreshProbes  = 2
)

// beginRefreshLocked starts the anchor refresh of round k when its plan d
// wants one (plan.RefreshWanted) and the coordinator can have it: a
// natprobe registration with two probes left for the side, a live link, the
// handshake time for the wait and the round's window — the final round
// included — the assist channel the request travels on (not
// under NoAssistRelay) and the mechanism itself (not under NoRefresh).
// It sends the requests, keeps d and its inputs for planning the
// round again, and reports whether the round now waits.
func (s *Session) beginRefreshLocked(k int, gen uint64, d decision, cin ClassifyInput, in RoundInput, now time.Duration) bool {
	st := &s.st
	a := align([2]*rttEstimator{&st.rtt[0], &st.rtt[1]}, s.ablate.NoRTTAlign)
	wait := min(refreshGap+max(a.rtt[0], a.rtt[1], s.udpRTTLocked(0), s.udpRTTLocked(1))+refreshSlack, maxRefreshWait)
	if !d.ok || d.dec.Stop != "" || s.handle == nil || s.ablate.NoAssistRelay || s.ablate.NoRefresh || s.remainingLocked(now) < wait+d.dec.Window {
		return false
	}
	wanted := plan.RefreshWanted(in, d.dec, now-s.regAt)
	// The round is planned again by d's planner: the default one when the
	// planner panicked deciding it.
	rf := refreshState{k: k, gen: gen, d: d, p: d.planner, cin: cin}
	asked := false
	for r, fams := range wanted {
		l := st.links[r]
		if len(fams) == 0 || l == nil || l.dead || st.gone[r] || s.handle.ProbesLeft(roleOf(r)) < refreshProbes*len(fams) {
			continue
		}
		for _, f := range fams {
			req := protocol.Assist{SessionID: s.id, From: protocol.RoleServer, Kind: protocol.AssistRefresh, Round: uint8(k), Family: f}
			if l.send(req) != nil {
				continue
			}
			rf.want[r][famIndex(f)], asked = true, true
			st.ctr.Refreshes++
		}
	}
	if !asked {
		return false
	}
	// A planner that panicked stays replaced while the round waits, and
	// the round is planned again on the default planner's classification.
	s.takeDecisionLocked(d)
	rf.pending, rf.asked = true, rf.want
	rf.until, rf.cap = now+wait, now+wait
	st.refresh = rf
	// The round waits for the refresh: the stage deadline — a stuck
	// planner's, or round 1's readies' — must not fall inside the wait.
	st.deadline = max(st.deadline, rf.until+refreshSlack)
	s.rearmLocked(now)
	return true
}

// refreshEventLocked takes a refresh probe natprobe saw: the second byte of
// its SANDWICH TLV says which of the two it is.
func (s *Session) refreshEventLocked(ev nat.SandwichEvent, now time.Duration) {
	rf := &s.st.refresh
	r, ok := roleIndex(ev.Role)
	fi := famIndex(protocol.FamilyOf(ev.Observed.Addr()))
	if !ok || !rf.pending || int(ev.Round) != rf.k || !rf.want[r][fi] {
		return
	}
	rf.got[r][fi][ev.Phase-nat.RefreshFirst] = refreshProbe{addr: ev.Observed, at: s.since(ev.At) - s.regAt}
	s.refreshWaitLocked(now)
}

// refreshWaitLocked ends the wait when no asked side and family can bring
// more: each has its second probe — the newest point, which is
// all the planner needs — or its first and refreshGap plus one and a half
// UDP round trips passed since it came; a family without a probe holds the
// wait until the cap. Otherwise it moves the end of the wait to the latest
// of those bounds, never past the cap.
func (s *Session) refreshWaitLocked(now time.Duration) {
	rf := &s.st.refresh
	var end time.Duration
	for r := range rf.want {
		for fi, want := range rf.want[r] {
			first, second := rf.got[r][fi][0], rf.got[r][fi][1]
			switch {
			case !want || second.addr.IsValid():
			case first.addr.IsValid():
				end = max(end, s.regAt+first.at+refreshGap+s.udpRTTLocked(r)*3/2)
			default:
				end = rf.cap
			}
		}
	}
	if end = min(end, rf.cap); now >= end {
		s.refreshDoneLocked(now)
		return
	}
	rf.until = end
	s.rearmLocked(now)
}

// udpRTTLocked is side r's UDP round trip as the probe phase measured it
// (PairFacts.ProbeRTTMs, the fastest probe of its report), or its control
// link's when the report had none.
func (s *Session) udpRTTLocked(r int) time.Duration {
	if ms := s.st.pair.ProbeRTTMs[roleOf(r)]; ms > 0 {
		return time.Duration(ms) * time.Millisecond
	}
	a := align([2]*rttEstimator{&s.st.rtt[0], &s.st.rtt[1]}, s.ablate.NoRTTAlign)
	return a.rtt[r]
}

// refreshDoneLocked ends the wait — every probe came, or the time ran out —
// and has the session goroutine plan the round again.
func (s *Session) refreshDoneLocked(now time.Duration) {
	st := &s.st
	st.refresh.pending, st.refresh.ready = false, true
	st.work.refreshed = true
	s.rearmLocked(now)
	s.kick()
}

// refreshInputLocked turns the probes that came into the planner's input:
// a family of a side counts with one probe or both, but not with
// two on different IPs, which say nothing about one allocator.
func (s *Session) refreshInputLocked() [2][]plan.AnchorRefresh {
	rf := &s.st.refresh
	var out [2][]plan.AnchorRefresh
	for r := range rf.got {
		for fi, g := range rf.got[r] {
			a, b := g[0], g[1]
			if !rf.want[r][fi] || !a.addr.IsValid() && !b.addr.IsValid() ||
				a.addr.IsValid() && b.addr.IsValid() && a.addr.Addr() != b.addr.Addr() {
				continue
			}
			fam := protocol.FamilyOf(b.addr.Addr())
			if !b.addr.IsValid() {
				fam = protocol.FamilyOf(a.addr.Addr())
			}
			out[r] = append(out[r], plan.AnchorRefresh{Family: fam, First: a.addr, Second: b.addr, FirstAt: a.at, SecondAt: b.at})
		}
	}
	return out
}

// afterRefresh plans the waiting round again with what the refresh found —
// or keeps the plan it had, when nothing came — and goes on: round 1 takes
// the re-aimed windows into the go its readies wait for, a later round
// starts. The refresh stays ready until then, which holds round 1's go.
func (s *Session) afterRefresh() {
	var (
		rf    refreshState
		in    RoundInput
		ok    bool
		found bool
	)
	now := s.since(s.c.set.clock.Now())
	func() {
		s.mu.Lock()
		defer s.mu.Unlock()
		st := &s.st
		if !st.refresh.ready || st.refresh.gen != st.gen {
			return
		}
		// The round's input as of now: it fires later than first planned.
		rf, in, ok = st.refresh, s.roundInputLocked(st.refresh.k, now), true
		in.Refresh = s.refreshInputLocked()
		found = len(in.Refresh[0])+len(in.Refresh[1]) > 0
	}()
	if !ok {
		return
	}
	d := rf.d
	if found {
		d = s.decide(rf.p, rf.cin, in)
	}
	nowT := s.c.set.clock.Now()
	var fx effects
	func() {
		s.mu.Lock()
		defer s.mu.Unlock()
		st := &s.st
		if !st.refresh.ready || st.refresh.gen != rf.gen || st.refresh.k != rf.k {
			return
		}
		st.refresh.ready = false
		if rf.k == 1 {
			fx = s.reanchorRound1Locked(rf.gen, d, found, nowT)
			return
		}
		fx = s.applyRoundLocked(rf.gen, rf.k, d, nowT)
	}()
	s.apply(fx)
}

// reanchorRound1Locked re-aims round 1 with the plan d made from its
// anchor refresh, when the refresh brought anything (found): only the
// anchors and spans of predict stages change (reanchored), the clients
// having bound their sockets for the summaries' plans; then, when both
// readies are in, the go leaves. A failed or stopping plan leaves the
// summaries' plans as they are: the round was granted with them.
func (s *Session) reanchorRound1Locked(gen uint64, d decision, found bool, nowT time.Time) effects {
	st := &s.st
	var fx effects
	if st.gen != gen || st.state != StateSummarized {
		return fx
	}
	now := s.since(nowT)
	// A planner that panicked planning the round again is replaced like
	// in every other round.
	s.takeDecisionLocked(d)
	if found && d.ok && d.dec.Stop == "" {
		for r := range st.cur.plans {
			if pl, ok := reanchored(st.cur.plans[r], d.dec.Sides[r]); ok {
				st.cur.plans[r], st.cur.reanchored[r] = pl, true
			}
		}
	}
	if st.ready[0] && st.ready[1] {
		fx.merge(s.startRoundLocked(now))
		return fx
	}
	s.rearmLocked(now)
	return fx
}

// reanchored is plan with each predict stage aimed where the planner's
// family sides of the same role now aim the stage at the same position —
// a new anchor, the span cut to the shorter one, never grown — and whether
// anything changed (protocol.RoundPlan.Reanchor).
func reanchored(plan protocol.RoundPlan, sides []protocol.FamilySide) (protocol.RoundPlan, bool) {
	changed := false
	for fi, fs := range plan.Sides {
		i := slices.IndexFunc(sides, func(x protocol.FamilySide) bool { return x.Family == fs.Family })
		if i < 0 || len(sides[i].Stages) != len(fs.Stages) {
			continue
		}
		for si, st := range fs.Stages {
			ns := sides[i].Stages[si]
			span := min(ns.Span, st.Span)
			if st.Kind != protocol.StagePredict || ns.Kind != protocol.StagePredict || span == 0 || ns.Anchor == st.Anchor && span == st.Span {
				continue
			}
			plan, changed = plan.Reanchor(fi, si, ns.Anchor, span), true
		}
	}
	return plan, changed
}
