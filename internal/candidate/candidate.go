package candidate

import (
	"net/netip"
	"time"

	"github.com/djylb/holepunch/protocol"
)

// Kind is a candidate's discovery class, ordered by base priority (direct
// LAN > observed > peer_targets > predicted > random > birthday). The
// kinds are exactly the ones the runtime produces: a peer's port
// mapping has no kind of its own — it arrives in a peer_targets assist and
// ranks as KindTargets, or as KindLAN for an upstream-LAN candidate whose
// hairpin self-test failed — and neither has a peer's public-local
// address. A candidate that has returned a packet is Responsive and ranks
// above every non-responsive candidate. KindOverlay, a peer's address on an
// overlay network, stands apart from the order: Table.Best takes it
// only when nothing else answered or when it is much faster.
type Kind uint8

const (
	KindUnknown   Kind = iota
	KindBirthday       // random birthday target
	KindRandom         // random spray target
	KindPredicted      // predicted port
	KindTargets        // a target or window port of a peer_targets assist
	KindObserved       // verified observed public endpoint
	KindLAN            // same-subnet LAN address
	KindOverlay        // overlay address: Tailscale, WireGuard, ZeroTier, a virtual bridge, 100.64/10
)

var kindNames = [...]string{"unknown", "birthday", "random", "predicted", "targets", "observed", "lan", "overlay"}

// String returns the lowercase kind name.
func (k Kind) String() string {
	if int(k) < len(kindNames) {
		return kindNames[k]
	}
	return "invalid"
}

// Base scores, one tier per kind. Responsive adds respBoost, which lifts any
// candidate above every non-responsive one. Two different tiers differ by at
// least 50, more than the 32-point selection hysteresis, and a
// tier's candidates share its reason, so "switch only when the score lead
// exceeds 32 and the reason differs" reduces to "switch only to a higher
// tier", which betterForNomination applies directly.
const (
	respBoost    = 100000
	scoreOverlay = 750 // its own tier: Best compares it with the others by RTT, never by score
	scoreLAN     = 700
	scoreObs     = 550
	scoreTargets = 500
	scorePred    = 400
	scoreRand    = 300
	scoreBday    = 200
	scoreNone    = 1
)

func (k Kind) baseScore() int {
	switch k {
	case KindOverlay:
		return scoreOverlay
	case KindLAN:
		return scoreLAN
	case KindObserved:
		return scoreObs
	case KindTargets:
		return scoreTargets
	case KindPredicted:
		return scorePred
	case KindRandom:
		return scoreRand
	case KindBirthday:
		return scoreBday
	default: // KindUnknown or out of range
		return scoreNone
	}
}

// CandKind maps to the wire PathInfo.cand_kind value.
// A candidate of unknown origin that merely responded reports as
// peer_reflexive.
func (c *Candidate) CandKind() protocol.CandKind {
	switch c.Kind {
	case KindOverlay:
		return protocol.CandOverlay
	case KindLAN:
		return protocol.CandLAN
	case KindObserved:
		return protocol.CandDirect
	case KindTargets:
		return protocol.CandTargets
	case KindPredicted:
		return protocol.CandPredicted
	case KindRandom:
		return protocol.CandRandom
	case KindBirthday:
		return protocol.CandBirthday
	default: // KindUnknown or out of range
		if c.Responsive {
			return protocol.CandPeerReflexive
		}
		return protocol.CandDirect
	}
}

// State is a candidate's lifecycle state.
type State uint8

const (
	StateDiscovered State = iota
	StateSucceeded        // a peer packet was received on this pair
	StateNominated        // the pair of the current nomination or adoption
	StateConfirmed        // the pair this session confirmed
	StateClosed           // the pair's local socket failed reading (Manager.ReadFailed); never nominated again
)

// Candidate is one (local, remote) pair.
type Candidate struct {
	Local, Remote netip.AddrPort
	Family        protocol.Family
	Kind          Kind
	Reason        string
	State         State
	Responsive    bool
	SuccessCount  int
	FirstSeen     time.Time
	LastSeen      time.Time
	SucceededAt   time.Time
	MinRTT        time.Duration // smallest success RTT on this pair (0 = none)
	NomFailures   int           // epoch rolls of this pair; each doubles its rto
	CooldownUntil time.Time
	// Path, PeerSock and Described are the caller's description of the
	// pair (Manager.Describe): the network it runs over and the peer's
	// socket on it. Only the choice of extra paths reads them.
	Path      protocol.PathKind
	PeerSock  uint8
	Described bool
}

// Score is the nomination score: base kind score plus the responsive boost.
func (c *Candidate) Score() int {
	s := c.Kind.baseScore()
	if c.Responsive {
		s += respBoost
	}
	return s
}

type pairKey struct{ local, remote netip.AddrPort }

// betterForNomination reports whether cand should replace best as the nominee:
// the higher score wins; equal scores fall back to more successes, fewer
// nomination failures, the earlier success, the earlier discovery and the
// address order, so the choice is deterministic.
func betterForNomination(cand, best *Candidate) bool {
	if cand == nil {
		return false
	}
	if best == nil {
		return true
	}
	if diff := cand.Score() - best.Score(); diff != 0 {
		return diff > 0
	}
	if cand.SuccessCount != best.SuccessCount {
		return cand.SuccessCount > best.SuccessCount
	}
	if cand.NomFailures != best.NomFailures {
		return cand.NomFailures < best.NomFailures
	}
	if !cand.SucceededAt.Equal(best.SucceededAt) {
		switch {
		case cand.SucceededAt.IsZero():
			return false
		case best.SucceededAt.IsZero():
			return true
		}
		return cand.SucceededAt.Before(best.SucceededAt)
	}
	if !cand.FirstSeen.Equal(best.FirstSeen) {
		return cand.FirstSeen.Before(best.FirstSeen)
	}
	if c := cand.Local.Compare(best.Local); c != 0 {
		return c < 0
	}
	return cand.Remote.Compare(best.Remote) < 0
}

// maxCandidates bounds a session's candidate table. Entries come only from
// authenticated peer packets (one per (local, remote) pair), so a realistic
// session holds a few dozen; the bound keeps a long or hostile session from
// growing the table and the O(n) Best without limit.
const maxCandidates = 256

// Table holds the candidates of one session (every family) and chooses the
// nominee. It is plain state; the Manager owns one.
type Table struct {
	cands map[pairKey]*Candidate
}

func newTable() *Table { return &Table{cands: make(map[pairKey]*Candidate)} }

// Observe records or refreshes a candidate from a plan stage (not yet
// responsive). It never lowers an existing candidate's kind.
func (t *Table) Observe(now time.Time, local, remote netip.AddrPort, fam protocol.Family, kind Kind) *Candidate {
	c := t.getOrCreate(local, remote, fam, now)
	c.LastSeen = now
	if kind.baseScore() > c.Kind.baseScore() {
		c.Kind = kind
		c.Reason = kind.String()
	}
	return c
}

// Success records that a peer packet arrived on (local, remote): the candidate
// becomes responsive and succeeded. rttSample (now-echo_ts) is folded into the
// pair's minimum when positive.
func (t *Table) Success(now time.Time, local, remote netip.AddrPort, fam protocol.Family, rttSample time.Duration) *Candidate {
	c := t.getOrCreate(local, remote, fam, now)
	c.LastSeen = now
	c.Responsive = true
	if c.SucceededAt.IsZero() {
		c.SucceededAt = now
	}
	c.SuccessCount++
	if rttSample > 0 && (c.MinRTT == 0 || rttSample < c.MinRTT) {
		c.MinRTT = rttSample
	}
	if c.State == StateDiscovered {
		c.State = StateSucceeded
	}
	if c.Reason == "" || c.Kind == KindUnknown {
		c.Reason = "responsive"
	}
	return c
}

// An overlay path must be this much faster to win over the best other path:
// its RTT at most 4/5 of that path's.
const (
	overlayRTTNum = 4
	overlayRTTDen = 5
)

// Best returns the responsive candidate to nominate among those neither
// closed nor in cooldown: the highest-scoring one that is no overlay
// candidate, unless an overlay candidate answered and either nothing else
// did or its measured RTT is at most 0.8 × that candidate's. An
// overlay path runs through a tunnel the caller may not want to depend on,
// so it wins only when it is the only path or clearly the faster one.
func (t *Table) Best(now time.Time) *Candidate {
	var best, overlay *Candidate
	for _, c := range t.cands {
		if !c.Responsive || c.State == StateClosed || c.CooldownUntil.After(now) {
			continue
		}
		if c.Kind == KindOverlay {
			if betterForNomination(c, overlay) {
				overlay = c
			}
		} else if betterForNomination(c, best) {
			best = c
		}
	}
	switch {
	case overlay == nil:
		return best
	case best == nil:
		return overlay
	case overlay.MinRTT > 0 && best.MinRTT > 0 && overlay.MinRTT*overlayRTTDen <= best.MinRTT*overlayRTTNum:
		return overlay
	}
	return best
}

// Len returns the number of tracked candidates.
func (t *Table) Len() int { return len(t.cands) }

func (t *Table) get(local, remote netip.AddrPort) *Candidate {
	return t.cands[pairKey{local, remote}]
}

func (t *Table) getOrCreate(local, remote netip.AddrPort, fam protocol.Family, now time.Time) *Candidate {
	k := pairKey{local, remote}
	if c, ok := t.cands[k]; ok {
		return c
	}
	if len(t.cands) >= maxCandidates {
		t.evict()
	}
	c := &Candidate{Local: local, Remote: remote, Family: fam, State: StateDiscovered, FirstSeen: now, LastSeen: now}
	t.cands[k] = c
	return c
}

// evict drops the least useful candidate to make room: never the nominated
// or confirmed pair; a closed one first, then a non-responsive one before a
// responsive one; among those, the one seen least recently, and the address
// order last, so the choice does not depend on the map order.
func (t *Table) evict() {
	var victim *Candidate
	for _, c := range t.cands {
		if c.State == StateNominated || c.State == StateConfirmed {
			continue
		}
		if victim == nil || evictBefore(c, victim) {
			victim = c
		}
	}
	if victim != nil {
		delete(t.cands, pairKey{victim.Local, victim.Remote})
	}
}

// evictBefore reports whether c is less useful than v.
func evictBefore(c, v *Candidate) bool {
	if cc, vc := c.State == StateClosed, v.State == StateClosed; cc != vc {
		return cc
	}
	if c.Responsive != v.Responsive {
		return !c.Responsive
	}
	if !c.LastSeen.Equal(v.LastSeen) {
		return c.LastSeen.Before(v.LastSeen)
	}
	if d := c.Local.Compare(v.Local); d != 0 {
		return d < 0
	}
	return c.Remote.Compare(v.Remote) < 0
}

// closeLocal moves every pair of the local socket to StateClosed.
func (t *Table) closeLocal(local netip.AddrPort) {
	for _, c := range t.cands {
		if c.Local == local {
			c.State = StateClosed
		}
	}
}
