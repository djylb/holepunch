package candidate

import (
	"net/netip"
	"slices"
	"time"

	"github.com/djylb/holepunch/protocol"
)

// Extra paths. With
// Config.MaxPaths above 1 a session hands over, besides the primary path
// chosen exactly as with one path, up to MaxPaths-1 extra paths, each a
// pair that already carried the peer's packets and was confirmed on itself:
//
//   - the initiator picks them when it nominates the primary path, the
//     most different first, and sends each a nominate with its slot
//     (PATH_SLOT) on its own pair, along with the primary's nominate and
//     its resends;
//   - the responder adopts one only once it adopted the primary path of
//     the same epoch, when the pair is an observed one, no duplicate of the
//     paths it holds and within its room, and answers with an accept of
//     that slot on that pair; the primary's accept announces the room
//     (PATHS);
//   - the initiator confirms the primary path on its accept as always; with
//     extra paths still unanswered and room for them it sends their
//     nominates once more — the accept proves the adoption they need — and
//     waits at most one rto of the slowest pair for their accepts
//     (PhaseSettling), at most 150 ms; its first ready carries the slots
//     it commits (PATHS), every later ready the same ones;
//   - the responder commits exactly those slots on the ready it confirms
//     on.
//
// The ready is the one decision both sides take, so both hand over the same
// set; only the rare responder that confirms without any ready (an
// upper-layer datagram, a "false quiet") commits none. Every packet
// of it is a handshake packet: no punching, no round and no budget beyond
// the handshake reserve.

// extraPath is one extra path of a campaign (initiator) or an adoption
// (responder).
type extraPath struct {
	c        *Candidate
	slot     uint8
	accepted bool // initiator: the responder accepted it
}

// Describe records what the caller knows of a pair besides its packets:
// the kind of network it runs over and the peer's socket on it (the header
// sock of the peer's packets). Only the choice of extra paths reads them.
// A pair not in the table is ignored.
func (m *Manager) Describe(local, remote netip.AddrPort, path protocol.PathKind, peerSock uint8) {
	if m.inert {
		return
	}
	if c := m.tab.get(local, remote); c != nil {
		c.Path, c.PeerSock, c.Described = path, peerSock, true
	}
}

// Extras returns the committed extra paths, in slot order: the initiator's
// once its ready went out, the responder's once it confirmed.
func (m *Manager) Extras() []Candidate {
	out := make([]Candidate, 0, len(m.committed))
	for _, c := range m.committed {
		out = append(out, *c)
	}
	return out
}

// route is the kind of network a pair runs over, for telling paths apart: a
// port mapping of the peer counts as public, because through the same two
// sockets the peer sees one pair either way.
func (c *Candidate) route() protocol.PathKind {
	switch {
	case c.Path == protocol.PathPortmap:
		return protocol.PathPublic
	case c.Path != "":
		return c.Path
	}
	return c.Kind.PathKind()
}

// duplicate reports whether two pairs are the same path: the same
// family and kind of network through the same socket at either end — this
// side's local socket, or the peer's as its packets name it.
func duplicate(a, b *Candidate) bool {
	if a.Family != b.Family || a.route() != b.route() {
		return false
	}
	return a.Local == b.Local || a.Described && b.Described && a.PeerSock == b.PeerSock
}

func duplicateOfAny(c *Candidate, held []*Candidate) bool {
	for _, h := range held {
		if duplicate(c, h) {
			return true
		}
	}
	return false
}

// held returns the primary path and the extra paths, the set a new extra
// path must differ from.
func (m *Manager) held() []*Candidate {
	out := []*Candidate{m.cur}
	for _, x := range m.extras {
		out = append(out, x.c)
	}
	return out
}

// eligibleExtra reports whether c may become an extra path: it answered, is
// neither closed nor cooling down, and is no other path of the session.
func eligibleExtra(c *Candidate, now time.Time) bool {
	return c.Responsive && c.State == StateSucceeded && !c.CooldownUntil.After(now)
}

// pickExtras chooses the campaign's extra paths after the primary path:
// repeatedly the eligible pair that is no duplicate of those chosen and
// adds the most — a family not yet covered, then a kind of network not yet
// covered, an overlay path last, then the nomination order.
func (m *Manager) pickExtras(now time.Time) {
	m.extras = nil
	for len(m.extras) < m.cfg.MaxPaths-1 {
		chosen := m.held()
		var best *Candidate
		for _, c := range m.tab.cands {
			if eligibleExtra(c, now) && !duplicateOfAny(c, chosen) && moreDifferent(c, best, chosen) {
				best = c
			}
		}
		if best == nil {
			return
		}
		m.extras = append(m.extras, extraPath{c: best, slot: uint8(len(m.extras) + 1)})
	}
}

// moreDifferent reports whether c adds more to chosen than best does.
func moreDifferent(c, best *Candidate, chosen []*Candidate) bool {
	if best == nil {
		return true
	}
	newFam := func(x *Candidate) bool {
		for _, h := range chosen {
			if h.Family == x.Family {
				return false
			}
		}
		return true
	}
	newRoute := func(x *Candidate) bool {
		for _, h := range chosen {
			if h.route() == x.route() {
				return false
			}
		}
		return true
	}
	if a, b := newFam(c), newFam(best); a != b {
		return a
	}
	if a, b := newRoute(c), newRoute(best); a != b {
		return a
	}
	if a, b := c.Kind != KindOverlay, best.Kind != KindOverlay; a != b {
		return a
	}
	return betterForNomination(c, best)
}

// nominations are the primary path's nominate and those of the pending
// extra paths.
func (m *Manager) nominations() []Action {
	return append([]Action{m.action(SendNominate)}, m.extraNominations()...)
}

// extraNominations are the nominates of the extra paths not yet accepted.
func (m *Manager) extraNominations() []Action {
	var acts []Action
	for _, x := range m.extras {
		if !x.accepted {
			acts = append(acts, m.extraAction(SendNominate, x))
		}
	}
	return acts
}

func (m *Manager) extraAction(k ActionKind, x extraPath) Action {
	return Action{Kind: k, Epoch: m.epoch, Local: x.c.Local, Remote: x.c.Remote, Family: x.c.Family, Slot: x.slot}
}

// settled reports whether the initiator has every accept it can expect: all
// its extra paths answered, or as many as the responder has room for.
func (m *Manager) settled() bool {
	n := 0
	for _, x := range m.extras {
		if x.accepted {
			n++
		}
	}
	return n == len(m.extras) || n >= m.room
}

// settleWait bounds the wait for the extra paths' accepts after the primary
// path's: one rto of the slowest pending pair, at most 150 ms — their
// nominates go out again at the primary path's accept, so their accepts are
// due by then.
func (m *Manager) settleWait() time.Duration {
	w := minRTO
	for _, x := range m.extras {
		if x.accepted {
			continue
		}
		rtt := noSampleRTT
		if x.c.MinRTT > 0 {
			rtt = x.c.MinRTT
		}
		w = max(w, clampDur(2*rtt, minRTO, maxRTO))
	}
	return w
}

// commitExtras commits the accepted extra paths (initiator, at the first
// ready), each no duplicate of those before it.
func (m *Manager) commitExtras() {
	var ok []extraPath
	for _, x := range m.extras {
		if x.accepted && x.c.State != StateClosed {
			ok = append(ok, x)
		}
	}
	m.commit(ok)
}

// commitSlots commits the adopted extra paths whose slots the ready lists
// (responder).
func (m *Manager) commitSlots(paths uint8) {
	var ok []extraPath
	for _, x := range m.extras {
		if paths&(1<<x.slot) != 0 && x.c.State != StateClosed {
			ok = append(ok, x)
		}
	}
	// Adopted in arrival order, committed in slot order: the initiator's.
	slices.SortFunc(ok, func(a, b extraPath) int { return int(a.slot) - int(b.slot) })
	m.commit(ok)
}

func (m *Manager) commit(xs []extraPath) {
	held := []*Candidate{m.cur}
	m.committed, m.paths = nil, 0
	for _, x := range xs {
		if duplicateOfAny(x.c, held) {
			continue
		}
		held = append(held, x.c)
		x.c.State = StateConfirmed
		m.committed = append(m.committed, x.c)
		m.paths |= 1 << x.slot
	}
}

// isCommitted reports whether (local, remote) is a committed extra path.
func (m *Manager) isCommitted(local, remote netip.AddrPort) bool {
	for _, c := range m.committed {
		if c.Local == local && c.Remote == remote {
			return true
		}
	}
	return false
}

// RecvExtraNominate (responder) adopts the extra path of slot on (local,
// remote) at epoch e: only within the adoption of the primary path at that
// epoch, for an observed pair that is no duplicate of the paths held, while
// there is room. A repeat for the adopted pair re-sends one accept; another
// pair for an adopted slot is ignored (first come wins).
func (m *Manager) RecvExtraNominate(now time.Time, e uint16, slot uint8, local, remote netip.AddrPort) []Action {
	if !m.responder || m.confirmed || !m.adopted || e != m.adoptEpoch || slot == 0 || int(slot) >= protocol.MaxPaths {
		return nil
	}
	for _, x := range m.extras {
		if x.slot == slot {
			if x.c.Local == local && x.c.Remote == remote {
				return []Action{m.extraAction(SendAccept, x)}
			}
			return nil
		}
	}
	c := m.tab.get(local, remote)
	if c == nil || len(m.extras) >= m.cfg.MaxPaths-1 || !eligibleExtra(c, now) || duplicateOfAny(c, m.held()) {
		return nil
	}
	c.LastSeen = now
	x := extraPath{c: c, slot: slot}
	m.extras = append(m.extras, x)
	return []Action{m.extraAction(SendAccept, x)}
}

// RecvExtraAccept (initiator) records the accept of the extra path of slot
// at the current epoch from its pair; the last one awaited sends ready.
func (m *Manager) RecvExtraAccept(now time.Time, e uint16, slot uint8, local, remote netip.AddrPort) []Action {
	if m.inert || m.responder || e != m.epoch || (m.phase != PhaseNominating && m.phase != PhaseSettling) {
		return nil
	}
	for i := range m.extras {
		x := &m.extras[i]
		if x.slot != slot || x.c.Local != local || x.c.Remote != remote {
			continue
		}
		x.accepted = true
		if m.phase == PhaseSettling && m.settled() {
			return m.startReadying(now)
		}
		return nil
	}
	return nil
}

// dropExtras removes the uncommitted extra paths of a socket that can no
// longer read; an initiator left with every accept it can expect sends
// ready.
func (m *Manager) dropExtras(now time.Time, local netip.AddrPort) []Action {
	n := len(m.extras)
	keep := m.extras[:0]
	for _, x := range m.extras {
		if x.c.Local != local {
			keep = append(keep, x)
		}
	}
	m.extras = keep
	if len(keep) < n && !m.responder && m.phase == PhaseSettling && m.settled() {
		return m.startReadying(now)
	}
	return nil
}
