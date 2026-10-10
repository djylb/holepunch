package candidate

import (
	"net/netip"
	"time"

	"github.com/djylb/holepunch/protocol"
)

// Phase is the nomination/handover phase of the session.
type Phase uint8

const (
	PhasePunching   Phase = iota
	PhaseCollect          // initiator: collecting after the first success
	PhaseNominating       // initiator: sending nominate
	PhaseSettling         // initiator: confirmed, awaiting the extra paths' accepts before ready
	PhaseReadying         // initiator: confirmed, sending ready, awaiting handover
	PhaseAdopted          // responder: accepted a nomination
	PhaseConfirmed        // responder: confirmed, bursting handover_ack
	PhaseDone             // handed over
	PhaseFailed           // handover_timeout
)

// ActionKind is a UDP action the caller must perform.
type ActionKind uint8

const (
	SendNominate ActionKind = iota
	SendAccept
	SendReady
	SendAck
	Confirm  // stop all active sends and emit round_result{confirmed}
	HandOver // hand the winning socket to the upper layer
	Fail     // give up (handover_timeout)
)

// Action is one instruction returned by the state machine.
type Action struct {
	Kind        ActionKind
	Epoch       uint16
	Local       netip.AddrPort
	Remote      netip.AddrPort
	Family      protocol.Family
	ConfirmedBy protocol.HandoverEvidence // HandOver: ack | upper_layer | quiet | ready
	Reason      protocol.Reason           // Fail
	// Slot is the extra-path slot of a SendNominate or SendAccept
	// (PATH_SLOT); 0 for the primary path.
	Slot uint8
	// Paths is PATHS: on the primary path's SendAccept the responder's
	// room for extra paths, on SendReady the committed extra slots (bit k
	// for slot k); 0 for none.
	Paths uint8
}

// Config parameterises the state machine. Zero fields
// take the defaults and the others are clamped to the ranges of those
// tables. The quiet inference (500 ms) and the first-burst gap (10 ms) are
// fixed by the protocol and not configurable.
type Config struct {
	// Role is protocol.RoleInitiator or protocol.RoleResponder. Any other
	// role gives a Manager that never acts: every method returns no action.
	Role               protocol.Role
	HandoverTimeout    time.Duration // handover deadline from the local Confirm: default 2 s, [500 ms, 10 s]
	EpochCooldown      time.Duration // same-pair cooldown after an epoch roll: default 500 ms, [250 ms, 2 s]
	MaxNominateResends int           // resends without an accept before the epoch rolls: default 3, [2, 6]
	// MaxPaths is how many confirmed paths the session hands over: the
	// primary path and up to MaxPaths-1 extra paths. Default 1,
	// [1, protocol.MaxPaths]. With 1 the machine behaves
	// as if extra paths did not exist.
	MaxPaths int
}

func (c Config) normalized() Config {
	c.HandoverTimeout = defaultClamp(c.HandoverTimeout, 2*time.Second, 500*time.Millisecond, 10*time.Second)
	c.EpochCooldown = defaultClamp(c.EpochCooldown, 500*time.Millisecond, 250*time.Millisecond, 2*time.Second)
	switch {
	case c.MaxNominateResends <= 0:
		c.MaxNominateResends = 3
	case c.MaxNominateResends < 2:
		c.MaxNominateResends = 2
	case c.MaxNominateResends > 6:
		c.MaxNominateResends = 6
	}
	c.MaxPaths = min(max(c.MaxPaths, 1), protocol.MaxPaths)
	return c
}

// Fixed timing of the handshake.
const (
	firstBurstGap = 10 * time.Millisecond  // the ×2 first send of nominate, accept and ready
	quietTimeout  = 500 * time.Millisecond // I's quiet inference
	noSampleRTT   = 100 * time.Millisecond // rtt_udp without a sample on the pair
	minRTO        = 40 * time.Millisecond
	maxRTO        = 150 * time.Millisecond
	maxBackoffRTO = 1200 * time.Millisecond // rto after epoch rolls of a pair
	readyMinGap   = 20 * time.Millisecond   // a repeated accept re-sends ready at most this often

	// R bursts handover_ack at 0, 15 and 30 ms and hands over after the
	// last; up to two extra acks answer extra readies at once.
	ackBurstStep = 15 * time.Millisecond
	maxExtraAcks = 2

	// I hands over ackSpread after its first handover_ack once it has the
	// third, or ackWindow after the first at the latest: R's burst
	// ends 30 ms after its first ack, so by then R's read loop has stopped
	// and I's first upper-layer datagram cannot be swallowed by it.
	ackSpread = 30 * time.Millisecond
	ackWindow = 45 * time.Millisecond
)

// Manager is the per-session nomination/handover state machine. It is pure:
// the caller injects time into every method and performs the returned
// actions, and it re-arms its single timer at NextDeadline after every call.
type Manager struct {
	cfg       Config
	inert     bool // the role is neither initiator nor responder
	responder bool
	tab       *Table
	phase     Phase
	epoch     uint16
	cur       *Candidate
	firstRTT  time.Duration // RTT of the first success (collection-window estimate)

	confirmed bool

	// timers (absolute instants; zero = inactive)
	secondBurstAt time.Time
	collectAt     time.Time
	resendAt      time.Time
	handoverAt    time.Time
	ackDoneAt     time.Time // initiator: hand over on the acks received so far
	lastRemoteAt  time.Time

	nomResends  int
	readySent   int
	lastReadyAt time.Time
	winnerDead  bool // the winning socket failed reading: quiet proves nothing

	// initiator: handover_acks of the current epoch
	acks       int
	firstAckAt time.Time

	// responder: the ack burst after Confirm
	ackAt      []time.Time
	ackIdx     int
	extraAcks  int
	adoptEpoch uint16
	adopted    bool

	// Extra paths (paths.go): the initiator's of the current campaign or
	// the responder's adopted at adoptEpoch, by slot order; the room the
	// responder announced; the end of the initiator's wait for their
	// accepts; the committed ones and their PATHS bits.
	extras    []extraPath
	room      int
	settleAt  time.Time
	committed []*Candidate
	paths     uint8
}

// NewManager returns a Manager in the punching phase.
func NewManager(cfg Config) *Manager {
	m := &Manager{cfg: cfg.normalized(), tab: newTable(), phase: PhasePunching}
	switch cfg.Role {
	case protocol.RoleInitiator:
	case protocol.RoleResponder:
		m.responder = true
	default:
		m.inert = true
	}
	return m
}

// Table exposes the candidate table for observation.
func (m *Manager) Table() *Table { return m.tab }

// Phase returns the current phase.
func (m *Manager) Phase() Phase { return m.phase }

// Epoch returns the current nomination epoch.
func (m *Manager) Epoch() uint16 { return m.epoch }

// Confirmed reports whether this session has confirmed a path.
func (m *Manager) Confirmed() bool { return m.confirmed }

// Winner returns the winning candidate — the primary path — once confirmed.
func (m *Manager) Winner() (Candidate, bool) {
	if m.cur == nil || !m.confirmed {
		return Candidate{}, false
	}
	return *m.cur, true
}

// NextDeadline returns the instant at which Tick next has work, and false
// when no timer is armed (punching before the first success, handed over,
// failed). The instant may be at or before the caller's now: Tick is then
// due at once. Every method may move the deadline, so the caller re-reads it
// after each call and re-arms one timer at it; this keeps the 10 ms first
// burst, the 15/30 ms acks and the rto resends exact instead of quantized to
// a polling period.
func (m *Manager) NextDeadline() (time.Time, bool) {
	ev, at := m.earliest()
	return at, ev != evNone
}

// rto is the resend timeout on the current pair: clamp(2·rtt_udp, 150)
// ms, where rtt_udp is the pair's minimum sample or 100 ms without one,
// doubled for each epoch roll the pair has been through and capped at
// 1200 ms. Without the backoff an RTT above four rto would
// roll every epoch before its accept could arrive, forever.
func (m *Manager) rto() time.Duration {
	rtt := noSampleRTT
	k := 0
	if m.cur != nil {
		if m.cur.MinRTT > 0 {
			rtt = m.cur.MinRTT
		}
		k = m.cur.NomFailures
	}
	r := clampDur(2*rtt, minRTO, maxRTO)
	for ; k > 0 && r < maxBackoffRTO; k-- {
		r *= 2
	}
	return min(r, maxBackoffRTO)
}

// nomDelay is the collection window after the first success: clamp(rtt, 60,
// 250) ms, or 100 ms with no sample.
func (m *Manager) nomDelay() time.Duration {
	if m.firstRTT <= 0 {
		return noSampleRTT
	}
	return clampDur(m.firstRTT, 60*time.Millisecond, 250*time.Millisecond)
}

// Observe records a planned candidate (not yet responsive).
func (m *Manager) Observe(now time.Time, local, remote netip.AddrPort, fam protocol.Family, kind Kind) {
	if m.inert {
		return
	}
	m.tab.Observe(now, local, remote, fam, kind)
}

// Success records a received peer packet on (local, remote). For the initiator
// it starts the collection window on the first success. rttSample (now-echo_ts)
// may be 0 when unknown.
func (m *Manager) Success(now time.Time, local, remote netip.AddrPort, fam protocol.Family, rttSample time.Duration) {
	if m.inert {
		return
	}
	m.tab.Success(now, local, remote, fam, rttSample)
	if m.cur != nil && remote == m.cur.Remote && local == m.cur.Local {
		m.lastRemoteAt = now
	}
	if !m.responder && m.phase == PhasePunching {
		if rttSample > 0 {
			m.firstRTT = rttSample
		}
		m.phase = PhaseCollect
		m.collectAt = now.Add(m.nomDelay())
	}
}

// Touch records that any packet arrived from remote (feeds the quiet inference).
func (m *Manager) Touch(now time.Time, remote netip.AddrPort) {
	if m.cur != nil && remote == m.cur.Remote {
		m.lastRemoteAt = now
	}
}

// ReadFailed records that the read loop of the local socket ended on a
// non-timeout error. Every pair of that socket moves
// to StateClosed and is never nominated again.
//
//   - Before Confirm, an initiator whose nominated pair lost its socket
//     nominates the next best pair at a new epoch (or waits for one); a
//     responder keeps its adoption and its accept resends, which leaves the
//     initiator to roll the epoch and keeps it from inferring a false quiet.
//   - After Confirm the initiator no longer accepts quiet as evidence: it
//     hands over only on handover_acks or an upper-layer datagram — which a
//     socket that cannot read will not deliver — and otherwise fails at
//     handover_timeout. A responder's handover rests on the ready it
//     already received and is unchanged.
func (m *Manager) ReadFailed(now time.Time, local netip.AddrPort) []Action {
	if m.inert {
		return nil
	}
	m.tab.closeLocal(local)
	acts := m.dropExtras(now, local)
	if m.cur == nil || m.cur.Local != local {
		return acts
	}
	switch m.phase {
	case PhaseNominating:
		return m.renominate(now)
	case PhaseSettling, PhaseReadying:
		m.winnerDead = true
	case PhasePunching, PhaseCollect, PhaseAdopted, PhaseConfirmed, PhaseDone, PhaseFailed:
		// Only an initiator between nomination and handover reacts.
	}
	return acts
}

// ---- Tick ----

type eventKind uint8

const (
	evNone eventKind = iota
	evCollect
	evSecondBurst
	evResend
	evQuiet
	evHandoverTimeout
	evAckHandover
	evAck
	evSettle
)

// Tick fires every timer due at now and returns the resulting actions.
func (m *Manager) Tick(now time.Time) []Action {
	var acts []Action
	for range 1024 {
		ev, at := m.earliest()
		if ev == evNone || at.After(now) {
			break
		}
		acts = append(acts, m.fire(ev, now)...)
	}
	return acts
}

func (m *Manager) earliest() (eventKind, time.Time) {
	best := evNone
	var bestAt time.Time
	consider := func(ev eventKind, at time.Time) {
		if at.IsZero() {
			return
		}
		if best == evNone || at.Before(bestAt) {
			best, bestAt = ev, at
		}
	}
	switch m.phase {
	case PhaseCollect:
		consider(evCollect, m.collectAt)
	case PhaseNominating, PhaseAdopted:
		consider(evSecondBurst, m.secondBurstAt)
		consider(evResend, m.resendAt)
	case PhaseSettling:
		consider(evResend, m.resendAt)
		consider(evHandoverTimeout, m.handoverAt)
		consider(evSettle, m.settleAt)
	case PhaseReadying:
		consider(evSecondBurst, m.secondBurstAt)
		consider(evResend, m.resendAt)
		consider(evHandoverTimeout, m.handoverAt)
		consider(evAckHandover, m.ackDoneAt)
		if m.readySent >= 2 && !m.lastRemoteAt.IsZero() && !m.winnerDead {
			consider(evQuiet, m.lastRemoteAt.Add(quietTimeout))
		}
	case PhaseConfirmed:
		if m.ackIdx < len(m.ackAt) {
			consider(evAck, m.ackAt[m.ackIdx])
		}
	case PhasePunching, PhaseDone, PhaseFailed:
		// No timer of this machine runs.
	}
	return best, bestAt
}

func (m *Manager) fire(ev eventKind, now time.Time) []Action {
	switch ev {
	case evCollect:
		return m.startNominating(now)
	case evSecondBurst:
		return m.fireSecondBurst(now)
	case evResend:
		return m.fireResend(now)
	case evQuiet:
		return m.handOver(protocol.ConfirmedByQuiet)
	case evAckHandover:
		return m.handOver(protocol.ConfirmedByAck)
	case evHandoverTimeout:
		m.phase = PhaseFailed
		m.clearTimers()
		return []Action{{Kind: Fail, Reason: protocol.ReasonHandoverTimeout}}
	case evSettle:
		return m.startReadying(now)
	default: // evAck
		return m.fireAck()
	}
}

func (m *Manager) startNominating(now time.Time) []Action {
	best := m.tab.Best(now)
	if best == nil {
		m.phase = PhasePunching
		m.collectAt = time.Time{}
		return nil
	}
	return m.beginNominate(now, best)
}

// beginNominate starts a nomination campaign for best at the next epoch.
func (m *Manager) beginNominate(now time.Time, best *Candidate) []Action {
	m.cur = best
	m.cur.State = StateNominated
	m.epoch++
	m.phase = PhaseNominating
	m.nomResends = 0
	m.secondBurstAt = now.Add(firstBurstGap)
	m.resendAt = now.Add(m.rto())
	m.pickExtras(now)
	return m.nominations()
}

func (m *Manager) fireSecondBurst(now time.Time) []Action {
	m.secondBurstAt = time.Time{}
	switch m.phase {
	case PhaseNominating:
		return m.nominations()
	case PhaseAdopted:
		return []Action{m.action(SendAccept)}
	default: // PhaseReadying
		m.readySent++
		m.lastReadyAt = now
		return []Action{m.action(SendReady)}
	}
}

func (m *Manager) fireResend(now time.Time) []Action {
	switch m.phase {
	case PhaseNominating:
		// MaxNominateResends resends (after the ×2 first burst) without an
		// accept roll the epoch; the last resend is still sent before
		// rolling.
		if m.nomResends >= m.cfg.MaxNominateResends {
			return m.rollEpoch(now)
		}
		m.nomResends++
		m.resendAt = now.Add(m.rto())
		return m.nominations()
	case PhaseSettling:
		m.resendAt = now.Add(m.rto())
		return m.extraNominations()
	case PhaseAdopted:
		m.resendAt = now.Add(m.rto())
		return []Action{m.action(SendAccept)}
	default: // PhaseReadying
		m.readySent++
		m.lastReadyAt = now
		m.resendAt = now.Add(m.rto())
		return []Action{m.action(SendReady)}
	}
}

// rollEpoch puts the current pair in cooldown, counts the roll against it
// (its next campaign backs its rto off) and re-nominates the next best
// candidate at a higher epoch (unanswered nominates -> epoch+1).
func (m *Manager) rollEpoch(now time.Time) []Action {
	m.cur.NomFailures++
	m.cur.CooldownUntil = now.Add(m.cfg.EpochCooldown)
	return m.renominate(now)
}

// renominate releases the current pair and nominates the best remaining one
// at the next epoch; with only cooling-down pairs left it waits for the
// first cooldown to expire, and with none it returns to punching.
func (m *Manager) renominate(now time.Time) []Action {
	if m.cur.State == StateNominated {
		m.cur.State = StateSucceeded
	}
	if best := m.tab.Best(now); best != nil {
		return m.beginNominate(now, best)
	}
	m.cur, m.extras = nil, nil
	m.secondBurstAt, m.resendAt = time.Time{}, time.Time{}
	if at, ok := m.nextCooldownExpiry(now); ok {
		m.phase, m.collectAt = PhaseCollect, at
	} else {
		m.phase, m.collectAt = PhasePunching, time.Time{}
	}
	return nil
}

// nextCooldownExpiry returns when the first responsive, open pair leaves its
// cooldown.
func (m *Manager) nextCooldownExpiry(now time.Time) (time.Time, bool) {
	var best time.Time
	for _, c := range m.tab.cands {
		if !c.Responsive || c.State == StateClosed {
			continue
		}
		if c.CooldownUntil.After(now) && (best.IsZero() || c.CooldownUntil.Before(best)) {
			best = c.CooldownUntil
		}
	}
	return best, !best.IsZero()
}

// fireAck sends the next scheduled ack of the responder's burst and hands
// over after the last one.
func (m *Manager) fireAck() []Action {
	m.ackIdx++
	acts := []Action{m.action(SendAck)}
	if m.ackIdx >= len(m.ackAt) {
		acts = append(acts, m.handOver(protocol.ConfirmedByReady)...)
	}
	return acts
}

// ---- events ----

// RecvNominate (responder) adopts a nomination at epoch e for (local, remote)
// when the pair is an observed one — a peer packet arrived on it — and e is
// not below the epoch it holds. A repeat at the current epoch for
// the same pair re-sends one accept; a different pair at the same epoch is
// ignored (first come wins); a higher epoch overrides the adoption.
//
// fam is the pair's family; the table already knows it from the pair's
// first packet, so it is not consulted.
func (m *Manager) RecvNominate(now time.Time, e uint16, local, remote netip.AddrPort, _ protocol.Family) []Action {
	if !m.responder || m.confirmed {
		return nil
	}
	if m.adopted {
		if e < m.adoptEpoch {
			return nil
		}
		if e == m.adoptEpoch {
			if local == m.cur.Local && remote == m.cur.Remote {
				return []Action{m.action(SendAccept)}
			}
			return nil
		}
	}
	c := m.tab.get(local, remote)
	if c == nil || !c.Responsive || c.State == StateClosed {
		return nil
	}
	if m.cur != nil && m.cur != c && m.cur.State == StateNominated {
		m.cur.State = StateSucceeded
	}
	if e != m.adoptEpoch {
		m.extras = nil // they belong to the adoption this one overrides
	}
	c.LastSeen = now
	m.cur = c
	m.cur.State = StateNominated
	m.adopted = true
	m.adoptEpoch = e
	m.epoch = e
	m.phase = PhaseAdopted
	m.lastRemoteAt = now
	m.secondBurstAt = now.Add(firstBurstGap)
	m.resendAt = now.Add(m.rto())
	return []Action{m.action(SendAccept)}
}

// RecvAccept (initiator) confirms on an accept of the current epoch from the
// nominated remote; in Readying, a repeat re-sends ready (at most every 20 ms).
// room is the accept's PATHS, the responder's room for extra paths: with extra
// paths pending and room for them, ready waits for their accepts
// (PhaseSettling).
func (m *Manager) RecvAccept(now time.Time, e uint16, remote netip.AddrPort, room uint8) []Action {
	if m.inert || m.responder || m.cur == nil || remote != m.cur.Remote || e != m.epoch {
		return nil
	}
	m.lastRemoteAt = now
	switch m.phase {
	case PhaseNominating:
		return m.confirmInitiator(now, room)
	case PhaseReadying:
		if now.Sub(m.lastReadyAt) >= readyMinGap {
			m.readySent++
			m.lastReadyAt = now
			return []Action{m.action(SendReady)}
		}
	case PhasePunching, PhaseCollect, PhaseSettling, PhaseAdopted, PhaseConfirmed, PhaseDone, PhaseFailed:
		// A stray or late accept is ignored.
	}
	return nil
}

func (m *Manager) confirmInitiator(now time.Time, room uint8) []Action {
	m.confirm()
	m.handoverAt = now.Add(m.cfg.HandoverTimeout)
	m.room = int(room)
	acts := []Action{m.action(Confirm)}
	if !m.settled() {
		// The accept proves the responder adopted this campaign: an extra
		// nominate that reached it before the primary path's did not count,
		// so the pending ones go out again now, and their accepts are due
		// within one rto of their pairs.
		m.phase = PhaseSettling
		m.settleAt = now.Add(m.settleWait())
		m.secondBurstAt = time.Time{}
		m.resendAt = now.Add(m.rto())
		return append(acts, m.extraNominations()...)
	}
	return append(acts, m.startReadying(now)...)
}

// startReadying commits the accepted extra paths and sends the first ready,
// which carries them.
func (m *Manager) startReadying(now time.Time) []Action {
	m.commitExtras()
	m.phase = PhaseReadying
	m.settleAt = time.Time{}
	m.readySent = 1
	m.lastReadyAt = now
	m.secondBurstAt = now.Add(firstBurstGap)
	m.resendAt = now.Add(m.rto())
	return []Action{m.action(SendReady)}
}

// RecvReady (responder) confirms on a ready of the adopted epoch from the
// adopted remote and starts the ack burst; a further ready of that epoch
// during the burst is answered by an extra ack at once (at most two). paths
// is the ready's PATHS: the extra paths the initiator committed, which the
// responder commits with it.
func (m *Manager) RecvReady(now time.Time, e uint16, remote netip.AddrPort, paths uint8) []Action {
	if !m.responder || m.cur == nil || remote != m.cur.Remote || e != m.adoptEpoch {
		return nil
	}
	m.lastRemoteAt = now
	switch m.phase {
	case PhaseAdopted:
		m.commitSlots(paths)
		return m.confirmResponder(now)
	case PhaseConfirmed:
		if m.extraAcks < maxExtraAcks {
			m.extraAcks++
			return []Action{m.action(SendAck)}
		}
	case PhasePunching, PhaseCollect, PhaseNominating, PhaseSettling, PhaseReadying, PhaseDone, PhaseFailed:
		// A stray or late ready is ignored.
	}
	return nil
}

func (m *Manager) confirmResponder(now time.Time) []Action {
	m.confirm()
	m.phase = PhaseConfirmed
	m.ackAt = []time.Time{now.Add(ackBurstStep), now.Add(2 * ackBurstStep)}
	m.ackIdx = 0
	m.stopResends()
	return []Action{m.action(Confirm), m.action(SendAck)}
}

// RecvHandoverAck (initiator) counts a handover_ack of the current epoch from
// the winning remote. It hands over 30 ms after the first ack once three
// arrived, and 45 ms after the first at the latest.
func (m *Manager) RecvHandoverAck(now time.Time, e uint16, remote netip.AddrPort) []Action {
	if m.inert || m.responder || m.phase != PhaseReadying || remote != m.cur.Remote || e != m.epoch {
		return nil
	}
	m.lastRemoteAt = now
	m.acks++
	switch m.acks {
	case 1:
		m.firstAckAt = now
		m.ackDoneAt = now.Add(ackWindow)
	case 3:
		if at := maxTime(now, m.firstAckAt.Add(ackSpread)); at.Before(m.ackDoneAt) {
			m.ackDoneAt = at
		}
	}
	if !m.ackDoneAt.After(now) {
		return m.handOver(protocol.ConfirmedByAck)
	}
	return nil
}

// RecvUpperLayer handles a non-holepunch datagram that arrived on local from
// remote: the winning remote, or once committed an extra path's pair.
// The initiator hands over at once: only a responder that already handed
// over sends one. A responder that adopted confirms and hands over; one in
// its ack burst hands over at once instead of reading more of the upper
// layer's datagrams. Before it knows the committed extra paths —
// adopted, without a ready — only the primary path counts and none is
// committed.
func (m *Manager) RecvUpperLayer(now time.Time, local, remote netip.AddrPort) []Action {
	if m.inert || m.cur == nil {
		return nil
	}
	if remote != m.cur.Remote {
		if !m.isCommitted(local, remote) {
			return nil
		}
	} else {
		m.lastRemoteAt = now
	}
	switch m.phase {
	case PhaseReadying, PhaseConfirmed:
		return m.handOver(protocol.ConfirmedByUpperLayer)
	case PhaseAdopted:
		m.confirm()
		m.phase = PhaseConfirmed
		m.stopResends()
		acts := []Action{m.action(Confirm)}
		return append(acts, m.handOver(protocol.ConfirmedByUpperLayer)...)
	case PhasePunching, PhaseCollect, PhaseNominating, PhaseSettling, PhaseDone, PhaseFailed:
		// Nothing to hand over yet, or already over.
	}
	return nil
}

// confirm is the session-level confirm gate. It is reached only
// from PhaseNominating or PhaseAdopted, which every confirmation leaves for
// good, and the responder refuses nominations once confirmed: being one
// machine per session, a second Confirm cannot occur, so there is no
// late-confirm counter.
func (m *Manager) confirm() {
	m.confirmed = true
	m.cur.State = StateConfirmed
}

func (m *Manager) handOver(by protocol.HandoverEvidence) []Action {
	m.phase = PhaseDone
	m.clearTimers()
	a := m.action(HandOver)
	a.ConfirmedBy = by
	return []Action{a}
}

func (m *Manager) action(k ActionKind) Action {
	a := Action{Kind: k, Epoch: m.epoch}
	if m.cur != nil {
		a.Local = m.cur.Local
		a.Remote = m.cur.Remote
		a.Family = m.cur.Family
	}
	switch {
	case k == SendReady:
		a.Paths = m.paths
	case k == SendAccept && m.cfg.MaxPaths > 1:
		a.Paths = uint8(m.cfg.MaxPaths - 1)
	}
	return a
}

// stopResends ends the responder's accept resends when it confirms.
func (m *Manager) stopResends() {
	m.secondBurstAt = time.Time{}
	m.resendAt = time.Time{}
}

func (m *Manager) clearTimers() {
	m.collectAt = time.Time{}
	m.settleAt = time.Time{}
	m.secondBurstAt = time.Time{}
	m.resendAt = time.Time{}
	m.handoverAt = time.Time{}
	m.ackDoneAt = time.Time{}
	m.ackAt, m.ackIdx = nil, 0
}

func clampDur(v, lo, hi time.Duration) time.Duration {
	return min(max(v, lo), hi)
}

// defaultClamp returns def for v ≤ 0, otherwise v clamped to [lo, hi].
func defaultClamp(v, def, lo, hi time.Duration) time.Duration {
	if v <= 0 {
		return def
	}
	return clampDur(v, lo, hi)
}

func maxTime(a, b time.Time) time.Time {
	if a.After(b) {
		return a
	}
	return b
}
