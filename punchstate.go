package holepunch

import (
	"net/netip"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/djylb/holepunch/internal/candidate"
	"github.com/djylb/holepunch/protocol"
)

// roundStats is one family's evidence in the current round, the material of
// round_result.families[].
type roundStats struct {
	hit        bool
	seenFrom   []netip.AddrPort
	peerSeenUs bool
	recv       int
	icmp       int
	drift      bool
	peerSeen   int             // peer_seen reports sent this round
	reobserve  reobservation   // the round's re-observation probe in flight
	remap      *protocol.Remap // the new primary mapping it showed, echoed in round_result
}

type sockCand struct {
	sock uint8
	cand uint16
}

type pairKey struct{ local, remote netip.AddrPort }

// punchState is the session's punching evidence, shared by the read loops,
// the nomination goroutine, the round goroutines and the orchestrator. It is
// created with the runtime and lives as long as it; until the summary opens
// it (activate) the read loops leave it alone. mu guards the maps and stats;
// no user code and no clock call runs under it. Every other file reads and
// writes it through the methods below; those that return collections return
// copies, except where a method says otherwise.
type punchState struct {
	active    atomic.Bool // set once the workers exist and the nomination goroutine runs (summary accepted)
	converged atomic.Bool // a valid peer packet arrived: spraying stops
	confirmed atomic.Bool
	firstPeer atomic.Bool
	rx        atomic.Int64 // valid peer packets, session total

	mu        sync.Mutex
	round     uint8 // 1 until the first go: what arrives before it belongs to round 1
	stats     map[protocol.Family]*roundStats
	hit       map[netip.AddrPort]bool // remotes a valid packet came from
	seenPairs map[pairKey]bool
	kinds     map[netip.AddrPort]candidate.Kind
	portmaps  map[netip.AddrPort]bool // targets of peer_targets{source: portmap}: their paths are portmap paths
	cands     map[sockCand]netip.AddrPort
	seenSrc   map[netip.AddrPort]bool              // every peer source of the session (attribution)
	remapped  map[protocol.Family][]netip.AddrPort // primary mappings re-observed and reported, at most one a round
	anyHit    bool
	peerSeen  bool
	icmpMax   int

	confirmAt   time.Time
	confirmPath protocol.PathInfo
	handedOver  *candidate.Action
	winner      candidate.Candidate   // the confirmed pair as the handover decision left it
	extras      []candidate.Candidate // the extra paths committed with handedOver
	failed      bool

	wake chan struct{}
}

func newPunchState() *punchState {
	return &punchState{
		stats: map[protocol.Family]*roundStats{}, hit: map[netip.AddrPort]bool{},
		seenPairs: map[pairKey]bool{}, kinds: map[netip.AddrPort]candidate.Kind{}, portmaps: map[netip.AddrPort]bool{},
		cands: map[sockCand]netip.AddrPort{}, seenSrc: map[netip.AddrPort]bool{},
		remapped: map[protocol.Family][]netip.AddrPort{}, wake: make(chan struct{}, 1), round: 1,
	}
}

// activate lets the read loops in once the workers exist and the
// nomination goroutine runs.
func (st *punchState) activate() { st.active.Store(true) }

// isActive reports whether the summary opened the punching state.
func (st *punchState) isActive() bool { return st.active.Load() }

// hasConverged reports whether a valid peer packet arrived: spraying stops.
func (st *punchState) hasConverged() bool { return st.converged.Load() }

// isConfirmed reports whether the local Confirm happened.
func (st *punchState) isConfirmed() bool { return st.confirmed.Load() }

// received is the number of valid peer packets of the session.
func (st *punchState) received() int64 { return st.rx.Load() }

// woken is the orchestrator's wake-up channel; notify signals it.
func (st *punchState) woken() <-chan struct{} { return st.wake }

// notify wakes the orchestrator.
func (st *punchState) notify() {
	select {
	case st.wake <- struct{}{}:
	default:
	}
}

// newRound starts the round's evidence; the previous round's is dropped.
func (st *punchState) newRound(round uint8, fams []protocol.Family) {
	st.mu.Lock()
	defer st.mu.Unlock()
	st.round = round
	st.stats = map[protocol.Family]*roundStats{}
	for _, f := range fams {
		st.stats[f] = &roundStats{}
	}
}

// statsFor is family f's evidence this round, created on first use; the
// caller holds mu.
func (st *punchState) statsFor(f protocol.Family) *roundStats {
	s := st.stats[f]
	if s == nil {
		s = &roundStats{}
		st.stats[f] = s
	}
	return s
}

// roundEvidence returns a copy of family f's evidence this round.
func (st *punchState) roundEvidence(f protocol.Family) roundStats {
	st.mu.Lock()
	defer st.mu.Unlock()
	rs := *st.statsFor(f)
	rs.seenFrom = slices.Clone(rs.seenFrom)
	rs.remap = cloneRemap(rs.remap)
	return rs
}

// planTarget records a planned target's kind and cand for later lookups.
func (st *punchState) planTarget(sock uint8, cand uint16, to netip.AddrPort, k candidate.Kind) {
	st.mu.Lock()
	if old, ok := st.kinds[to]; !ok || k > old {
		st.kinds[to] = k
	}
	st.cands[sockCand{sock, cand}] = to
	st.mu.Unlock()
}

// candFor returns the cand of a planned target remote of socket sock.
func (st *punchState) candFor(sock uint8, remote netip.AddrPort) (uint16, bool) {
	st.mu.Lock()
	defer st.mu.Unlock()
	for k, to := range st.cands {
		if to == remote && k.sock == sock {
			return k.cand, true
		}
	}
	return 0, false
}

// planned counts the planned targets of family f.
func (st *punchState) planned(f protocol.Family) int {
	st.mu.Lock()
	defer st.mu.Unlock()
	n := 0
	for to := range st.kinds {
		if f.Matches(to.Addr()) {
			n++
		}
	}
	return n
}

// notePortmap records a target the server sent as one of the peer's port
// mappings (peer_targets{source: portmap}).
func (st *punchState) notePortmap(to netip.AddrPort) {
	st.mu.Lock()
	st.portmaps[to] = true
	st.mu.Unlock()
}

// isPortmap reports whether to is one of the peer's port mappings that
// peer_targets named.
func (st *punchState) isPortmap(to netip.AddrPort) bool {
	st.mu.Lock()
	defer st.mu.Unlock()
	return st.portmaps[to]
}

// peerArrival is what one authentic peer packet changed in the evidence.
type peerArrival struct {
	kind       candidate.Kind // the planned target's kind, when known
	known      bool
	round      uint8
	first      bool // the session's first peer packet
	newPair    bool // the first packet on its (local, remote) pair
	reportSeen bool // the new pair goes into a peer_seen (at most peerSeenPerRound a round)
}

// notePeer records an authentic, fresh packet of the peer of family fam
// from `from` on the socket bound at local; success says it is a success
// packet.
func (st *punchState) notePeer(fam protocol.Family, local, from netip.AddrPort, success bool) peerArrival {
	st.rx.Add(1)
	first := !st.firstPeer.Swap(true)
	st.converged.Store(true)

	st.mu.Lock()
	defer st.mu.Unlock()
	rs := st.statsFor(fam)
	rs.recv++
	if success {
		rs.hit = true
		st.anyHit = true
	}
	if len(rs.seenFrom) < protocol.MaxSeenFrom && !slices.Contains(rs.seenFrom, from) {
		rs.seenFrom = append(rs.seenFrom, from)
	}
	st.seenSrc[from] = true
	st.hit[from] = true
	pk := pairKey{local, from}
	a := peerArrival{first: first, newPair: !st.seenPairs[pk], round: st.round}
	st.seenPairs[pk] = true
	a.reportSeen = a.newPair && rs.peerSeen < peerSeenPerRound
	if a.reportSeen {
		rs.peerSeen++
	}
	a.kind, a.known = st.kinds[from]
	return a
}

// notePeerSeen records a relayed peer_seen of family fam: the peer heard
// our target cand of socket sock. target is that planned target, now a hit;
// known is false when no such target was planned.
func (st *punchState) notePeerSeen(fam protocol.Family, sock uint8, cand uint16) (target netip.AddrPort, known bool) {
	st.mu.Lock()
	defer st.mu.Unlock()
	st.statsFor(fam).peerSeenUs = true
	st.peerSeen = true
	target, known = st.cands[sockCand{sock, cand}]
	if known {
		st.hit[target] = true
	}
	return target, known
}

// noteDrift marks family fam's evidence of the round with a mapping drift.
func (st *punchState) noteDrift(fam protocol.Family) {
	st.mu.Lock()
	st.statsFor(fam).drift = true
	st.mu.Unlock()
}

// noteICMP counts an ICMP soft signal of family fam.
func (st *punchState) noteICMP(fam protocol.Family) {
	st.mu.Lock()
	rs := st.statsFor(fam)
	rs.icmp++
	st.icmpMax = max(st.icmpMax, rs.icmp)
	st.mu.Unlock()
}

// heardOn reports whether a valid peer packet arrived on the socket bound
// at local: its pairs are candidates.
func (st *punchState) heardOn(local netip.AddrPort) bool {
	st.mu.Lock()
	defer st.mu.Unlock()
	for pk := range st.seenPairs {
		if pk.local == local {
			return true
		}
	}
	return false
}

// isHit reports whether a valid packet came from to.
func (st *punchState) isHit(to netip.AddrPort) bool {
	st.mu.Lock()
	defer st.mu.Unlock()
	return st.hit[to]
}

// hits counts the remotes a valid packet came from.
func (st *punchState) hits() int {
	st.mu.Lock()
	defer st.mu.Unlock()
	return len(st.hit)
}

// heardBack reports whether the peer heard us: a success packet came, or
// the server said the peer saw us.
func (st *punchState) heardBack() bool {
	st.mu.Lock()
	defer st.mu.Unlock()
	return st.anyHit || st.peerSeen
}

// sessionEvidence is the session-wide punching evidence that attribution
// reads.
type sessionEvidence struct {
	seenFrom int  // distinct peer sources
	icmpMax  int  // the most ICMP signals of one family in one round
	hit      bool // a success packet came
	peerSeen bool // the server relayed a peer_seen
}

// evidence returns the session-wide evidence.
func (st *punchState) evidence() sessionEvidence {
	st.mu.Lock()
	defer st.mu.Unlock()
	return sessionEvidence{seenFrom: len(st.seenSrc), icmpMax: st.icmpMax, hit: st.anyHit, peerSeen: st.peerSeen}
}

// beginReobserve registers the round's re-observation probe of family f to
// observer at `to` when f has had no peer packet this round, drawing its
// seq from next; ok is false when f has had one.
func (st *punchState) beginReobserve(f protocol.Family, observer uint8, to netip.AddrPort, next func() uint32) (seq uint32, ok bool) {
	st.mu.Lock()
	defer st.mu.Unlock()
	rs := st.statsFor(f)
	if rs.recv != 0 {
		return 0, false
	}
	seq = next()
	rs.reobserve = reobservation{seq: seq, observer: observer, to: to}
	return seq, true
}

// reobserveAck is an ack that may answer a re-observation probe.
type reobserveAck struct {
	from     netip.AddrPort // canonical
	mapped   netip.AddrPort // the mapping it shows, canonical
	echoSeq  uint32
	cookie   uint32
	observer uint16 // the ack's aux
	novel    bool   // mapped is a usable endpoint the summary did not verify
}

// matchReobserve consumes the ack of family f's re-observation probe in
// flight and reports whether it was that probe's. A novel mapping
// not reported before becomes the round's remap and drift evidence
// (fresh), at most one a round. round is the current round.
func (st *punchState) matchReobserve(f protocol.Family, ack reobserveAck) (matched, fresh bool, round uint8) {
	st.mu.Lock()
	defer st.mu.Unlock()
	rs := st.stats[f]
	if rs == nil || rs.reobserve.seq == 0 || ack.echoSeq != rs.reobserve.seq || ack.observer != uint16(rs.reobserve.observer) ||
		ack.from != rs.reobserve.to {
		return false, false, 0
	}
	observer := rs.reobserve.observer
	rs.reobserve = reobservation{}
	fresh = ack.novel && !slices.Contains(st.remapped[f], ack.mapped)
	if fresh {
		// At most one a round: the list stays within the wire's 8 rounds.
		st.remapped[f] = append(st.remapped[f], ack.mapped)
		rs.remap = &protocol.Remap{Observer: observer, Observed: ack.mapped, Cookie: ack.cookie}
		rs.drift = true
	}
	return true, fresh, st.round
}

// confirm records the local Confirm at `at` on path, then marks the
// session confirmed.
func (st *punchState) confirm(at time.Time, path protocol.PathInfo) {
	st.mu.Lock()
	st.confirmAt, st.confirmPath = at, path
	st.mu.Unlock()
	st.confirmed.Store(true)
}

func (st *punchState) confirmTime() time.Time {
	st.mu.Lock()
	defer st.mu.Unlock()
	return st.confirmAt
}

// path is the confirmed path as Confirm described it.
func (st *punchState) path() protocol.PathInfo {
	st.mu.Lock()
	defer st.mu.Unlock()
	return st.confirmPath
}

// handOver records the first handover decision with the confirmed pair and
// the committed extra paths, as the state machine held them then, and wakes
// the orchestrator.
func (st *punchState) handOver(a candidate.Action, winner candidate.Candidate, extras []candidate.Candidate) {
	st.mu.Lock()
	if st.handedOver == nil {
		st.handedOver, st.winner, st.extras = &a, winner, extras
	}
	st.mu.Unlock()
	st.notify()
}

// handoverFailed records the handover timeout as the state machine saw it
// and wakes the orchestrator.
func (st *punchState) handoverFailed() {
	st.mu.Lock()
	st.failed = true
	st.mu.Unlock()
	st.notify()
}

// outcome returns the handover decision, or whether the handover failed. The
// action is shared: it is written once, at the handover, and only read
// afterwards.
func (st *punchState) outcome() (*candidate.Action, bool) {
	st.mu.Lock()
	defer st.mu.Unlock()
	return st.handedOver, st.failed
}

// handedPaths returns the confirmed pair and the committed extra paths of
// the handover decision.
func (st *punchState) handedPaths() (candidate.Candidate, []candidate.Candidate) {
	st.mu.Lock()
	defer st.mu.Unlock()
	return st.winner, slices.Clone(st.extras)
}
