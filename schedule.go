package holepunch

import (
	"net/netip"
	"slices"
	"time"

	"github.com/djylb/holepunch/internal/candidate"
	"github.com/djylb/holepunch/internal/netaddr"
	"github.com/djylb/holepunch/internal/plan"
	"github.com/djylb/holepunch/internal/udpwire"
	"github.com/djylb/holepunch/protocol"
)

// The schedule of a family round: the stages expanded into packets.

// schedule expands the side's stages into its direct and spray items; the
// items of a fresh stage go out from the bound fresh sockets, by the index
// of their draw (nil where the bind failed).
func (fr *familyRound) schedule(fresh []*udpSock) (direct, spray []sendItem) {
	rt := fr.rt
	side, w := fr.side, fr.w
	delay := time.Duration(side.SendDelayMs) * time.Millisecond
	if rt.abl.NoRoleAssign || side.Role == protocol.SideReplyOnly {
		delay = 0
	}
	for si, st := range side.Stages {
		start := fr.run.fireAt.Add(max(time.Duration(st.AtMs)*time.Millisecond, delay))
		var hops []int
		if w.lowTTL && st.TTL > 0 && !rt.abl.NoRoleAssign {
			hops = rt.hopCycle(int(st.TTL))
		}
		adm := w.admitStage(rt, side, st)
		if adm.rejected > 0 {
			fr.reject(adm.rejected)
		}
		switch st.Kind {
		case protocol.StageDirect:
			direct = append(direct, fr.directItems(si, st, adm.targets, start, hops)...)
		case protocol.StagePredict, protocol.StageRandom:
			if adm.ip.IsValid() {
				spray = append(spray, fr.sprayItems(si, st, adm.ip, start, hops)...)
			}
		case protocol.StageFresh:
			if len(adm.targets) > 0 || adm.ip.IsValid() {
				direct = append(direct, fr.freshItems(si, st, adm, start, fresh)...)
			}
		case protocol.StageFreshPeer:
			if adm.ip.IsValid() {
				direct = append(direct, fr.freshPeerItems(si, st, adm.ip, start)...)
			}
		case protocol.StageReplyOnly:
		}
	}
	slices.SortStableFunc(direct, func(a, b sendItem) int { return a.due.Compare(b.due) })
	return direct, spray
}

// reject counts n targets of this round that admission refused: in the
// session's counters and in round_result.rejected, which tells the server
// when neither side has anything to send to.
func (fr *familyRound) reject(n int) {
	fr.rt.rejectTargets(fr.w, n)
	fr.rejected.Add(int32(n))
}

func (rt *runtime) rejectTargets(w *worker, n int) {
	w.fs.cnt.targetRejected.Add(int64(n))
	w.fs.cnt.drops[dropTargetRejected].Add(int64(n))
}

// directItems repeats each admitted target on every round socket at the
// stage's offsets, the k-th repeat with the k-th hop of a low-TTL
// stage; a LAN target, or a target of an unverified family, is sent from the
// primary socket only, at most its per-round cap.
func (fr *familyRound) directItems(si int, st protocol.Stage, targets []admittedTarget, start time.Time, hops []int) []sendItem {
	rt, w := fr.rt, fr.w
	var out []sendItem
	for _, at := range targets {
		t, ti, per := at.to, at.index, at.per
		cand, ok := udpwire.CandID(si, ti)
		if !ok {
			continue
		}
		reps := max(int(st.Repeats), 1)
		socks := fr.socks
		if per > 0 {
			reps = min(reps, per)
			socks = socks[:1]
		}
		kind := w.addrKind(t.Addr(), candidate.KindObserved)
		offsets := plan.DirectOffsets(fr.seed, si, ti, reps)
		if fr.paced != nil {
			offsets = fr.spread(start, reps)
		}
		for _, s := range socks {
			rt.punch.planTarget(s.id, cand, t, kind)
			for k, off := range offsets {
				out = append(out, sendItem{due: start.Add(off), sock: s, to: t, cand: cand, stage: txDirect, hops: hopAt(hops, k)})
			}
		}
		if per == 0 {
			out = append(out, fr.pacedItems(t, cand, reps, start, hops)...)
		}
	}
	return out
}

// pacedItems sends a Direct target from the round's paced sockets
// (FamilySide.OpenPerSec): slot j opens j/OpenPerSec after firing —
// or at the stage's start, when later — and sends its repeats spread over
// the rest of the window, which keeps its mapping alive and answers the
// peer's late sprays.
func (fr *familyRound) pacedItems(t netip.AddrPort, cand uint16, reps int, start time.Time, hops []int) []sendItem {
	var out []sendItem
	for j := 1; j < len(fr.paced); j++ {
		open := fr.run.fireAt.Add(time.Duration(j) * time.Second / time.Duration(max(fr.side.OpenPerSec, 1)))
		if open.Before(start) {
			open = start
		}
		for k, off := range fr.spread(open, reps) {
			out = append(out, sendItem{due: open.Add(off), slot: j, to: t, cand: cand, stage: txBirthday, hops: hopAt(hops, k)})
		}
	}
	return out
}

// spread returns reps offsets from from, evenly over the rest of the
// round's window: the first at once.
func (fr *familyRound) spread(from time.Time, reps int) []time.Duration {
	rest := max(fr.run.end.Sub(from), 0)
	out := make([]time.Duration, reps)
	for k := range out {
		out[k] = rest * time.Duration(k) / time.Duration(reps)
	}
	return out
}

// sprayItems expands a predict or random stage with the spray seed —
// a paired predict stage with the initiator's — excluding ports
// already sent to the IP, and spreads the targets over the round's sockets;
// the i-th target takes the i-th hop of a low-TTL stage.
func (fr *familyRound) sprayItems(si int, st protocol.Stage, ip netip.Addr, start time.Time, hops []int) []sendItem {
	rt, w := fr.rt, fr.w
	sentPorts := rt.sender.sentPorts(ip)
	in := plan.ExpandInput{
		Seed: fr.seed, StageIndex: si, Allow: w.allow,
		Exclude: func(p uint16) bool { _, ok := sentPorts[p]; return ok },
	}
	if st.Pair {
		// Both sides order a paired stage by the initiator's spray seed of the
		// round, so that their mappings target each other in pairs.
		in.PairSeed = fr.pairSeed()
		in.Responder = rt.codec.Role() == udpwire.RoleResponder
	}
	targets := plan.ExpandStage(st, in)
	stage, kind := sprayClass(st.Kind, len(fr.socks) > 1)
	out := make([]sendItem, 0, len(targets))
	for i, t := range targets {
		cand, ok := udpwire.CandID(si, i)
		if !ok {
			break
		}
		t = netaddr.Canon(t)
		s := fr.socks[i%len(fr.socks)]
		rt.punch.planTarget(s.id, cand, t, kind)
		out = append(out, sendItem{due: start, sock: s, to: t, cand: cand, stage: stage, hops: hopAt(hops, i)})
	}
	return out
}

// sprayClass is the counter stage and candidate kind of the targets of a
// predict or random stage of kind k; a random stage sprayed from more than
// one socket (multi) is the birthday.
func sprayClass(k protocol.StageKind, multi bool) (txStage, candidate.Kind) {
	switch {
	case k == protocol.StagePredict:
		return txPredict, candidate.KindPredicted
	case multi:
		return txBirthday, candidate.KindBirthday
	}
	return txRandom, candidate.KindRandom
}

// pairSeed is the initiator's spray seed of the round, which both sides draw a
// paired stage's order and the fresh sockets' ports from.
func (fr *familyRound) pairSeed() [8]byte {
	rt := fr.rt
	return udpwire.SpraySeed(rt.start.Token, rt.start.Wire.RouteID, udpwire.RoleInitiator, fr.run.plan.Round, fr.run.plan.Seed)
}

// freshItems sends a fresh stage from the bound fresh sockets: socket k
// sends Repeats packets to each admitted target, or to the stage's admitted
// IP and the k-th drawn port when the peer binds fresh sockets too — the two
// k-th sockets pair up.
func (fr *familyRound) freshItems(si int, st protocol.Stage, adm stageAdmission, start time.Time, fresh []*udpSock) []sendItem {
	rt := fr.rt
	targets := make([]netip.AddrPort, len(adm.targets))
	for i, at := range adm.targets {
		targets[i] = at.to
	}
	var ports []uint16
	if adm.ip.IsValid() {
		ports = plan.FreshPorts(fr.pairSeed(), len(fresh))
	}
	var out []sendItem
	for k, s := range fresh {
		cand, ok := udpwire.CandID(si, k)
		if s == nil || !ok {
			continue
		}
		to, kind := targets, candidate.KindObserved
		if ports != nil {
			to, kind = []netip.AddrPort{netip.AddrPortFrom(adm.ip, ports[k])}, candidate.KindPredicted
		}
		for ti, t := range to {
			rt.punch.planTarget(s.id, cand, t, kind)
			for _, off := range plan.DirectOffsets(fr.seed, si, k*len(to)+ti, int(max(st.Repeats, 1))) {
				out = append(out, sendItem{due: start.Add(off), sock: s, to: t, cand: cand, stage: txFresh})
			}
		}
	}
	return out
}

// freshPeerItems aims a fresh_peer stage at the peer's fresh sockets: from the
// primary socket, Repeats packets to the stage's IP and each drawn port.
func (fr *familyRound) freshPeerItems(si int, st protocol.Stage, ip netip.Addr, start time.Time) []sendItem {
	rt := fr.rt
	s := fr.socks[0]
	var out []sendItem
	for k, port := range plan.FreshPorts(fr.pairSeed(), int(st.Count)) {
		cand, ok := udpwire.CandID(si, k)
		if !ok {
			break
		}
		t := netip.AddrPortFrom(ip, port)
		rt.punch.planTarget(s.id, cand, t, candidate.KindPredicted)
		for _, off := range plan.DirectOffsets(fr.seed, si, k, int(max(st.Repeats, 1))) {
			out = append(out, sendItem{due: start.Add(off), sock: s, to: t, cand: cand, stage: txFresh})
		}
	}
	return out
}

// extraItems schedules peer_targets from the primary socket, now and at the
// Direct offsets after it, on the round's peer_targets quota: at most
// protocol.MaxPushPerRound targets a round, protocol.PushPackets packets each. The
// window ports go after the explicit targets, in the order of the round's
// spray seed (scatterWindows), and a batch beyond the quota loses its last
// ones: some window ports, drawn by that order, before any explicit target.
func (fr *familyRound) extraItems(targets []extraTarget, now time.Time) []sendItem {
	rt := fr.rt
	base := int(fr.extras.Load())
	targets = scatterWindows(fr.seed, base, targets)
	if over := len(targets) - max(protocol.MaxPushPerRound-base, 0); over > 0 {
		targets = targets[:len(targets)-over]
		fr.w.fs.cnt.drops[dropBudget].Add(int64(over))
	}
	var out []sendItem
	fr.extras.Add(int32(len(targets)))
	for i, t := range targets {
		cand, ok := udpwire.CandID(extraStageIndex, base+i)
		if !ok {
			break
		}
		rt.punch.planTarget(fr.socks[0].id, cand, t.to, t.kind)
		for _, off := range plan.DirectOffsets(fr.seed, extraStageIndex, base+i, protocol.PushPackets) {
			out = append(out, sendItem{due: now.Add(off), sock: fr.socks[0], to: t.to, cand: cand, stage: txDirect, quota: quotaTargets})
		}
	}
	slices.SortStableFunc(out, func(a, b sendItem) int { return a.due.Compare(b.due) })
	return out
}

// scatterWindows returns targets with the explicit targets first, in their
// order, and then the window ports of each IP in the order of the round's
// spray seed (plan.ScatterPorts): in Lo..Hi order
// a window would leave as the same run of adjacent ports in every session.
// index, the first peer_targets index of the batch, selects the seed's
// sub-stream, so that every batch of a round is scattered differently. The
// send gate's run guard (runs.go) still holds back a port that would extend
// a run.
func scatterWindows(seed [8]byte, index int, targets []extraTarget) []extraTarget {
	out := make([]extraTarget, 0, len(targets))
	var ips []netip.Addr
	ports := map[netip.Addr][]uint16{}
	kinds := map[netip.AddrPort]candidate.Kind{}
	for _, t := range targets {
		if !t.window {
			out = append(out, t)
			continue
		}
		ip := t.to.Addr()
		if _, ok := ports[ip]; !ok {
			ips = append(ips, ip)
		}
		ports[ip] = append(ports[ip], t.to.Port())
		kinds[t.to] = t.kind
	}
	for i, ip := range ips {
		for _, p := range plan.ScatterPorts(seed, index+i, ports[ip]) {
			to := netip.AddrPortFrom(ip, p)
			out = append(out, extraTarget{to: to, kind: kinds[to], window: true})
		}
	}
	return out
}

// hopCycle is the hop sequence of a low-TTL stage whose preferred hop is h: the
// hops the session allows — the server's low_ttl_hops intersected with
// Options.Policy's, protocol.Tighten — in their order, starting at h, or at the
// allowed hop nearest h (the smaller on a tie) when h is not one of them.
func (rt *runtime) hopCycle(h int) []int {
	hs := rt.policy.LowTTLHops
	if len(hs) == 0 {
		return nil
	}
	dist := func(v int) int { return max(v-h, h-v) }
	start := 0
	for i, v := range hs {
		if d, best := dist(v), dist(hs[start]); d < best || d == best && v < hs[start] {
			start = i
		}
	}
	return append(slices.Clone(hs[start:]), hs[:start]...)
}

// hopAt is the hop of the k-th packet of a stage cycling through hops, or 0
// (normal TTL) for a stage without low TTL.
func hopAt(hops []int, k int) int {
	if len(hops) == 0 {
		return 0
	}
	return hops[k%len(hops)]
}
