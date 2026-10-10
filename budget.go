package holepunch

import (
	"context"
	"errors"
	"net/netip"
	"sync"
	"time"

	"github.com/djylb/holepunch/internal/faultinject"
	"github.com/djylb/holepunch/internal/netaddr"
	"github.com/djylb/holepunch/internal/udpicmp"
	"github.com/djylb/holepunch/protocol"
	"github.com/djylb/holepunch/udpwire"
)

// sendClass is the budget class of a packet.
type sendClass uint8

const (
	// classInitiate: punch packets the session starts; bounded by
	// MaxPackets, the pps and new-target buckets, distinct targets and ports.
	classInitiate sendClass = iota
	// classReply: success replies; at most one per received seq (the replay
	// window guarantees it) and one per (socket, remote) per 20 ms; they use
	// pps tokens without waiting and do not count against MaxPackets.
	classReply
	// classHandshake: nominate, accept, ready, handover_ack; never blocked by
	// MaxPackets, bounded by their own reserve.
	classHandshake
	// classProbe: probes, keepalives, sandwich probes, hairpin; counted apart
	// and bounded by the prober (≤ 31 per family) and natprobe.
	classProbe
)

// Sender limits.
const (
	handshakeReserve = 256
	replyMinGap      = 20 * time.Millisecond
	newTargetBurst   = 16
	portWindow       = 10 * time.Second
	blockedAfter     = time.Second // every write failing this long while punching is udp_blocked
	nonWaitDebt      = 2           // tokens replies and handshakes may borrow from the pps bucket
)

var (
	errBudget      = errors.New("holepunch: packet budget exhausted")
	errRejected    = errors.New("holepunch: target rejected")
	errStopped     = errors.New("holepunch: initiation stopped")
	errSuppressed  = errors.New("holepunch: reply suppressed")
	errUnreachable = errors.New("holepunch: destination unreachable")
	errNoBudgetYet = errors.New("holepunch: no punching budget before the summary")
)

// Fault-injection point of the send gate.
const fiProbeSend = "probe.send"

// bucket is a token bucket on the session clock. A zero rate is unlimited.
// Reservations may drive it below zero: the deficit is the wait.
type bucket struct {
	rate, burst float64
	tokens      float64
	at          time.Time
}

func newBucket(rate, burst float64) bucket { return bucket{rate: rate, burst: burst, tokens: burst} }

func (b *bucket) refill(now time.Time) {
	if b.at.IsZero() {
		b.at = now
		return
	}
	if dt := now.Sub(b.at); dt > 0 {
		b.tokens = min(b.burst, b.tokens+dt.Seconds()*b.rate)
		b.at = now
	}
}

// reserve takes a token and returns how long until it is actually available.
func (b *bucket) reserve(now time.Time) time.Duration {
	if b.rate <= 0 {
		return 0
	}
	b.refill(now)
	b.tokens--
	if b.tokens >= 0 {
		return 0
	}
	return time.Duration(-b.tokens / b.rate * float64(time.Second))
}

// take takes a token without waiting, borrowing at most debt tokens.
func (b *bucket) take(now time.Time, debt float64) bool {
	if b.rate <= 0 {
		return true
	}
	b.refill(now)
	if b.tokens-1 < -debt {
		return false
	}
	b.tokens--
	return true
}

// sendQuota says which per-round quota an initiated packet draws on.
type sendQuota uint8

const (
	// quotaPlan: a packet of the round's planned stages. It draws on the
	// family's grant (FamilySide.MaxPackets and MaxDistinctPorts); refused
	// for packets, it means the plan was cut short: budget_hit.
	quotaPlan sendQuota = iota
	// quotaFollowUp: a follow-up punch after a peer_seen. It draws on the
	// grant like a planned packet, but its refusal cuts no plan short.
	quotaFollowUp
	// quotaTargets: a packet of a peer_targets assist. It never draws on the
	// grant: it has its own per-round room under the class ceiling
	// (roundCeiling), so pushed targets cannot cut the plan short.
	quotaTargets
)

// roundMeter is the per-family, per-round part of the gate: the round's
// packet grant, its rate buckets and the ports it sent to each peer IP.
// Guarded by sender.mu, except direct, which is read-only.
type roundMeter struct {
	fam        protocol.Family
	round      uint8
	maxPackets int // the grant of planned packets and follow-ups; 0 = none
	maxPorts   int // distinct ports per peer IP of grant-drawing packets; 0 = no limit
	granted    int // packets drawn on the grant
	sent       int // initiated packets of every quota (round_result.sent)
	budgetHit  bool
	pps        bucket
	newT       bucket
	ports      map[netip.Addr]*ipRound
	ceil       *roundCeiling

	direct map[netip.AddrPort]bool // the side's Direct targets: known ports to the run guard
}

// roundCeiling is the round's class ceiling as it binds peer_targets,
// shared by the round's families: the class's packets minus the
// families' grants, and the class's distinct ports per peer IP, counting
// the planned ports too. Guarded by sender.mu.
type roundCeiling struct {
	packets int // peer_targets packets still allowed this round
	ports   int // the class's distinct ports per peer IP; 0 = no limit
}

// newRoundCeiling is the room a round with class limits lim and the given
// per-family grants leaves to peer_targets.
func newRoundCeiling(lim protocol.ClassLimits, sides []protocol.FamilySide) *roundCeiling {
	granted := 0
	for _, s := range sides {
		granted += int(s.MaxPackets)
	}
	return &roundCeiling{packets: max(int(lim.MaxPackets)-granted, 0), ports: int(lim.MaxDistinctPorts)}
}

// ipRound is what one round sent to one peer IP: every port, marked when a
// grant-drawing packet used it, and how many ports are so marked.
type ipRound struct {
	used map[uint16]bool
	plan int
}

func newRoundMeter(fam protocol.Family, round uint8, side protocol.FamilySide, ceil *roundCeiling) *roundMeter {
	maxPorts := int(side.MaxDistinctPorts)
	if ceil.ports > 0 && (maxPorts == 0 || ceil.ports < maxPorts) {
		maxPorts = ceil.ports
	}
	direct := map[netip.AddrPort]bool{}
	for _, st := range side.Stages {
		if st.Kind == protocol.StageDirect {
			for _, t := range st.Targets {
				direct[netaddr.Canon(t)] = true
			}
		}
	}
	return &roundMeter{
		fam: fam, round: round, direct: direct, maxPackets: int(side.MaxPackets), maxPorts: maxPorts, ceil: ceil,
		pps:   newBucket(float64(side.MaxPPS), ppsBurst(int(side.MaxPPS))),
		newT:  newBucket(float64(side.MaxNewPerSec), newTargetBurst),
		ports: map[netip.Addr]*ipRound{},
	}
}

// ppsBurst is the depth of a pps bucket: max(pps/10, 8).
func ppsBurst(pps int) float64 { return float64(max(pps/10, 8)) }

// distinctPorts is the round's largest count of distinct ports to one IP.
func (m *roundMeter) distinctPorts() int {
	n := 0
	for _, r := range m.ports {
		n = max(n, len(r.used))
	}
	return n
}

// packetsLocked checks the packet quotas of one initiated packet; full says
// the session budget is spent. A planned packet refused here is budget_hit.
func (m *roundMeter) packetsLocked(q sendQuota, full bool) error {
	switch {
	case q == quotaTargets:
		if full || m.ceil.packets <= 0 {
			return errBudget
		}
	case full || m.maxPackets > 0 && m.granted >= m.maxPackets:
		if q == quotaPlan {
			m.budgetHit = true
		}
		return errBudget
	}
	return nil
}

// portOKLocked checks the per-IP distinct-port quotas of a packet to
// ip:port: grant-drawing packets count their own ports against the
// family's port grant, peer_targets count every port of the round against
// the class's.
func (m *roundMeter) portOKLocked(ip netip.Addr, port uint16, q sendQuota) bool {
	var r ipRound
	if p := m.ports[ip]; p != nil {
		r = *p
	}
	planned, seen := r.used[port]
	if q == quotaTargets {
		return seen || m.ceil.ports == 0 || len(r.used) < m.ceil.ports
	}
	return planned || m.maxPorts == 0 || r.plan < m.maxPorts
}

// useLocked records a packet to ip:port.
func (m *roundMeter) useLocked(ip netip.Addr, port uint16, q sendQuota) {
	r := m.ports[ip]
	if r == nil {
		r = &ipRound{used: map[uint16]bool{}}
		m.ports[ip] = r
	}
	if q == quotaTargets {
		if _, seen := r.used[port]; !seen {
			r.used[port] = false
		}
	} else if !r.used[port] {
		r.used[port] = true
		r.plan++
	}
	m.sent++
	if q == quotaTargets {
		m.ceil.packets--
	} else {
		m.granted++
	}
}

// ipPorts tracks the ports sent to one peer IP: ever (for expansion's
// exclusion) and within the sliding 10 s window.
type ipPorts struct {
	ever map[uint16]struct{}
	last map[uint16]time.Time
	q    []portUse
}

type portUse struct {
	port uint16
	at   time.Time
}

func (p *ipPorts) prune(now time.Time) {
	cut := now.Add(-portWindow)
	i := 0
	for ; i < len(p.q) && p.q[i].at.Before(cut); i++ {
		if t, ok := p.last[p.q[i].port]; ok && !t.After(p.q[i].at) {
			delete(p.last, p.q[i].port)
		}
	}
	p.q = p.q[i:]
}

func (p *ipPorts) use(port uint16, now time.Time) {
	p.ever[port] = struct{}{}
	p.last[port] = now
	p.q = append(p.q, portUse{port, now})
}

// classMark records a round's per-IP distinct-port ceiling for the sliding
// window rule: within any 10 s the ports to one IP stay within the highest
// ceiling of the rounds active in that window.
type classMark struct {
	at    time.Time
	ports int
}

type replyKey struct {
	sock uint8
	to   netip.AddrPort
}

// sender is the only UDP write path of the library: every packet — punch,
// reply, handshake, probe — passes its gate,
// is sealed with the session codec and written under the socket's write
// turn with a 100 ms deadline. It holds no goroutine and no timer of its
// own; a send waiting for tokens waits on the caller's goroutine and ctx.
// Each family's packets pass its lane one at a time, so that the run guard
// (runs.go) sees them in the order they leave.
type sender struct {
	rt    *runtime
	codec *udpwire.Codec
	lanes [2]*lane // by famIndex

	mu         sync.Mutex
	budget     protocol.Budget // the session budget; zero until the summary
	initiated  int
	handshakes int
	stopped    bool // local Confirm: initiation over
	pps        bucket
	newT       bucket
	targets    map[netip.AddrPort]struct{}
	perIP      map[netip.Addr]*ipPorts
	marks      []classMark
	replyAt    map[replyKey]time.Time
	recent     []time.Time // initiated sends within the last second, for PeakPPS
	peakPPS    int
	failSince  time.Time // first write failure since the last success
	lastOK     time.Time
	everFailed bool

	pool sync.Pool
}

func newSender(rt *runtime, codec *udpwire.Codec) *sender {
	return &sender{
		rt: rt, codec: codec, lanes: [2]*lane{newLane(), newLane()},
		targets: map[netip.AddrPort]struct{}{},
		perIP:   map[netip.Addr]*ipPorts{},
		replyAt: map[replyKey]time.Time{},
		pool:    sync.Pool{New: func() any { b := make([]byte, 0, udpwire.MinProbePacket+udpwire.MaxPlaintext); return &b }},
	}
}

// setBudget installs the session budget from the summary.
func (s *sender) setBudget(b protocol.Budget) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.budget = b
	s.pps = newBucket(float64(b.MaxPPS), ppsBurst(int(b.MaxPPS)))
	s.newT = newBucket(float64(b.MaxNewPerSec), newTargetBurst)
}

// startRound registers a round's distinct-port ceiling for the sliding window.
func (s *sender) startRound(now time.Time, classPorts int) {
	s.mu.Lock()
	s.marks = append(s.marks, classMark{now, classPorts})
	s.mu.Unlock()
}

// stop ends initiation at local Confirm: every later initiate send fails.
func (s *sender) stop() {
	s.mu.Lock()
	s.stopped = true
	s.mu.Unlock()
}

// windowMaxLocked is the highest per-IP port ceiling of the rounds within the
// last 10 s (the latest round's when none is that recent).
func (s *sender) windowMaxLocked(now time.Time) int {
	best := 0
	cut := now.Add(-portWindow)
	for _, m := range s.marks {
		if !m.at.Before(cut) {
			best = max(best, m.ports)
		}
	}
	if best == 0 && len(s.marks) > 0 {
		best = s.marks[len(s.marks)-1].ports
	}
	return best
}

// sentPorts returns the ports this session already sent to ip, for the
// expansion of predict and random stages.
func (s *sender) sentPorts(ip netip.Addr) map[uint16]struct{} {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := map[uint16]struct{}{}
	if p := s.perIP[ip]; p != nil {
		for k := range p.ever {
			out[k] = struct{}{}
		}
	}
	return out
}

// everSent reports whether the session initiated a packet to ip.
func (s *sender) everSent(ip netip.Addr) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.perIP[ip] != nil
}

// gateInitiateLocked checks an initiated packet against every limit and
// reserves it; the returned duration is how long to wait for its tokens.
func (s *sender) gateInitiateLocked(now time.Time, to netip.AddrPort, m *roundMeter, q sendQuota) (time.Duration, error) {
	switch {
	case s.stopped:
		return 0, errStopped
	case s.budget.MaxPackets == 0 || m == nil:
		return 0, errNoBudgetYet
	}
	if err := m.packetsLocked(q, s.initiated >= int(s.budget.MaxPackets)); err != nil {
		return 0, err
	}
	_, known := s.targets[to]
	if !known && len(s.targets) >= int(s.budget.MaxDistinctTargets) {
		return 0, errRejected
	}
	ip, port := to.Addr(), to.Port()
	if !m.portOKLocked(ip, port, q) {
		return 0, errRejected
	}
	pi := s.perIP[ip]
	if pi == nil {
		pi = &ipPorts{ever: map[uint16]struct{}{}, last: map[uint16]time.Time{}}
		s.perIP[ip] = pi
	}
	pi.prune(now)
	if _, in := pi.last[port]; !in {
		if w := s.windowMaxLocked(now); w > 0 && len(pi.last) >= w {
			return 0, errRejected
		}
	}
	wait := max(s.pps.reserve(now), m.pps.reserve(now))
	if !known {
		wait = max(wait, s.newT.reserve(now), m.newT.reserve(now))
		s.targets[to] = struct{}{}
	}
	m.useLocked(ip, port, q)
	pi.use(port, now)
	s.initiated++
	return wait, nil
}

// gateLocked applies the class rules; see sendClass.
func (s *sender) gateLocked(now time.Time, sock *udpSock, to netip.AddrPort, o *sendOpt) (time.Duration, error) {
	switch o.class {
	case classInitiate:
		return s.gateInitiateLocked(now, to, o.round, o.quota)
	case classReply:
		k := replyKey{sock.id, to}
		if last, ok := s.replyAt[k]; ok && now.Sub(last) < replyMinGap {
			return 0, errSuppressed
		}
		if !s.pps.take(now, nonWaitDebt) {
			return 0, errBudget
		}
		s.replyAt[k] = now
	case classHandshake:
		if s.handshakes >= handshakeReserve {
			return 0, errBudget
		}
		s.pps.take(now, float64(handshakeReserve))
		s.handshakes++
	case classProbe:
		// Bounded by the prober and natprobe, not here.
	}
	return 0, nil
}

// sendOpt says how to account and shape one packet.
type sendOpt struct {
	round *roundMeter // initiate only
	hops  int         // initiate only: low TTL for this packet, 0 = normal
	class sendClass
	stage txStage
	quota sendQuota // initiate only
}

// Send gates, seals and writes one packet built from h and t to `to` on
// sock. It fills the header's role, seq, timestamp and socket. A packet
// waiting for rate tokens waits on ctx; a canceled ctx returns at once. A
// packet the run guard holds back returns errRun before the gate has
// counted anything.
func (s *sender) Send(ctx context.Context, sock *udpSock, to netip.AddrPort, h *udpwire.Header, t *udpwire.TLVs, o sendOpt) error {
	if err := ctx.Err(); err != nil {
		return context.Cause(ctx)
	}
	l := s.lanes[famIndex(sock.fam)]
	if err := l.acquire(ctx); err != nil {
		return err
	}
	defer l.release()
	fc := &s.rt.fam(sock.fam).cnt
	now := s.rt.clk.Now()
	if !s.runAllows(l, to, &o, now) {
		return errRun
	}
	s.mu.Lock()
	wait, err := s.gateLocked(now, sock, to, &o)
	s.mu.Unlock()
	switch {
	case errors.Is(err, errRejected):
		fc.targetRejected.Add(1)
		fc.drop(dropTargetRejected)
		return err
	case errors.Is(err, errBudget):
		fc.drop(dropBudget)
		return err
	case err != nil:
		return err
	}
	if wait > 0 {
		if err := s.rt.sleep(ctx, s.rt.pace.spread(wait, 0.2)); err != nil {
			return err
		}
	}
	h.Role = s.codec.Role()
	h.Sock = sock.id
	if h.Seq == 0 {
		h.Seq = s.codec.NextSeq()
	}
	h.TS = s.codec.Now()
	h.LowTTL = o.hops > 0 && !sock.noLowTTL.Load()
	bp := s.pool.Get().(*[]byte)
	defer s.pool.Put(bp)
	pkt, err := s.codec.Seal((*bp)[:0], h, t, 0)
	if err != nil {
		return err
	}
	*bp = pkt[:0]
	if o.class == classProbe {
		if err := faultinject.Point(fiProbeSend); err != nil {
			return err
		}
	}
	wrapped, err := sock.write(ctx, pkt, to, o.hops)
	if err == nil {
		l.wrote(to, s.rt.clk.Now())
	}
	return s.account(sock, &o, wrapped, err)
}

// SendRaw writes an already sealed probe-class datagram (the prober seals
// its own probes) through the family's lane.
func (s *sender) SendRaw(ctx context.Context, sock *udpSock, to netip.AddrPort, pkt []byte) error {
	if err := ctx.Err(); err != nil {
		return context.Cause(ctx)
	}
	l := s.lanes[famIndex(sock.fam)]
	if err := l.acquire(ctx); err != nil {
		return err
	}
	defer l.release()
	o := sendOpt{class: classProbe, stage: txProbe}
	if !s.runAllows(l, to, &o, s.rt.clk.Now()) {
		return errRun
	}
	if err := faultinject.Point(fiProbeSend); err != nil {
		return err
	}
	wrapped, err := sock.write(ctx, pkt, to, 0)
	if err == nil {
		l.wrote(to, s.rt.clk.Now())
	}
	return s.account(sock, &o, wrapped, err)
}

// account counts the outcome of a write; one that left as an opener
// (wrapped) is still one packet of its class. A write that fails
// with the ICMP report of an earlier datagram (Windows, or a connected conn)
// is a soft signal like the same report on a read: the socket works, the
// report says nothing about this destination, so it neither drops the
// target nor counts towards udp_blocked. Only "no route" names this
// destination.
func (s *sender) account(sock *udpSock, o *sendOpt, wrapped bool, err error) error {
	fc := &s.rt.fam(sock.fam).cnt
	now := s.rt.clk.Now()
	if err != nil {
		if errors.Is(err, errDetached) || errors.Is(err, context.Canceled) {
			return err
		}
		fc.drop(dropSendErr)
		noRoute := udpicmp.IsNoRoute(err)
		if !noRoute && udpicmp.IsReport(err) {
			s.rt.noteICMP(sock)
			return err
		}
		s.mu.Lock()
		if s.failSince.IsZero() || s.lastOK.After(s.failSince) {
			s.failSince = now
		}
		s.everFailed = true
		s.mu.Unlock()
		if noRoute {
			return errUnreachable
		}
		return err
	}
	stage := o.stage
	if o.class == classInitiate && o.hops > 0 && !sock.noLowTTL.Load() {
		stage = txWarmup
	}
	fc.byStage[stage].Add(1)
	if wrapped {
		fc.openers.Add(1)
	}
	s.mu.Lock()
	s.lastOK = now
	if o.class == classInitiate {
		cut := now.Add(-time.Second)
		i := 0
		for i < len(s.recent) && s.recent[i].Before(cut) {
			i++
		}
		s.recent = append(s.recent[i:], now)
		s.peakPPS = max(s.peakPPS, len(s.recent))
	}
	s.mu.Unlock()
	if o.class == classInitiate {
		fc.tx.Add(1)
	}
	return nil
}

// writeBlocked reports whether every write has been failing for at least
// blockedAfter, which this side reports as round_result{fatal, udp_blocked}.
func (s *sender) writeBlocked(now time.Time) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.everFailed && !s.failSince.IsZero() && !s.lastOK.After(s.failSince) && now.Sub(s.failSince) >= blockedAfter
}

// usage reports the budget figures of Counters.
func (s *sender) usage() (distinct, peak, pct int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.budget.MaxPackets > 0 {
		pct = s.initiated * 100 / int(s.budget.MaxPackets)
	}
	return len(s.targets), s.peakPPS, pct
}
