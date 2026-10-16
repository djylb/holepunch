package e2e

import (
	"errors"
	"fmt"
	"math"
	"net/netip"
	"slices"
	"time"

	"github.com/djylb/holepunch"
	"github.com/djylb/holepunch/coord"
	"github.com/djylb/holepunch/nattest"
	"github.com/djylb/holepunch/protocol"
	"github.com/djylb/holepunch/udpwire"
)

// cellRun is one run of a cell: the finished session and what was measured.
type cellRun struct {
	c     *cell
	seed  int64
	w     *world
	sides [2]*side
	r     *run
	links [2]linkView
	m     runMetrics
	// dumped is the path of the failure dump written for an unsuccessful
	// run without violations.
	dumped string
}

// runMetrics are the per-run figures behind the KPIs.
type runMetrics struct {
	Reasons [2]protocol.Reason `json:"reasons"`
	// Measured is what natprobe measured of each side, in worlds that
	// record it (worldConfig.measure).
	Measured      [2]string            `json:"measured,omitzero"`
	Outcome       string               `json:"outcome"`
	Code          protocol.Reason      `json:"code,omitempty"`
	MaxClass      protocol.BudgetClass `json:"max_class"`
	Family        protocol.Family      `json:"family,omitempty"`
	CandKind      protocol.CandKind    `json:"cand_kind,omitempty"`
	RoundClasses  []string             `json:"round_classes,omitempty"`
	Variants      []string             `json:"variants,omitempty"`
	Violations    []string             `json:"violations,omitempty"`
	ConfirmMs     [2]float64           `json:"confirm_ms"`   // AttachSession call to return
	FromGoMs      [2]float64           `json:"from_go_ms"`   // first punch_go to return; -1 without a go
	Packets       [2]int               `json:"packets"`      // initiated packets (Counters.TxPackets)
	HostPackets   [2]uint64            `json:"host_packets"` // every UDP packet the host sent
	PeakPPSInit   [2]int               `json:"peak_pps_initiated"`
	PeakPPS1s     [2]int               `json:"peak_pps_1s"`
	PeakPPS100ms  [2]int               `json:"peak_pps_100ms"`
	DistinctPorts [2]int               `json:"distinct_ports_per_ip_10s"`
	MaxRun        [2]int               `json:"max_consecutive_run"`
	Filtered      [2]uint64            `json:"filtered_inbound"`
	PeerTargets   [2]int               `json:"peer_targets"`
	Paths         [2]int               `json:"paths"` // confirmed paths each side handed over; 0 on failure
	ScanBans      uint64               `json:"scan_bans"`
	Rounds        int                  `json:"rounds"`
	CtlFrames     uint64               `json:"control_frames"`
	Refreshes     uint64               `json:"refreshes,omitempty"` // anchor refreshes asked
	SkewMs        float64              `json:"first_send_skew_ms"`  // -1 when not measurable
	FireSkewMs    float64              `json:"fire_skew_ms"`        // -1 when not measurable
	ConfirmRound  int                  `json:"confirm_round"`
	PModel        float64              `json:"p_model,omitempty"`
	OK            bool                 `json:"ok"`
	HalfConfirmed bool                 `json:"half_confirmed"`
}

// maxClass returns the higher of two budget classes.
func maxClass(a, b protocol.BudgetClass) protocol.BudgetClass {
	if !a.Valid() || b.Valid() && b.Rank() > a.Rank() {
		return b
	}
	return a
}

// measure fills the run's metrics.
func (cr *cellRun) measure() {
	r, m := cr.r, &cr.m
	for i := range 2 {
		cr.links[i] = view(r.taps[i])
	}
	m.OK = r.out[0].ok() && r.out[1].ok()
	// Both sides are in the session from the later start (a late responder
	// does not count against the initiator's time).
	joined := r.out[0].start
	if r.out[1].start.After(joined) {
		joined = r.out[1].start
	}
	for i := range 2 {
		o := &r.out[i]
		m.Reasons[i] = o.reason()
		m.ConfirmMs[i] = ms(o.end.Sub(joined))
		m.FromGoMs[i] = -1
		if fg := r.res.Timings.FirstGo; !fg.IsZero() {
			m.FromGoMs[i] = ms(o.end.Sub(fg))
		}
		m.Packets[i] = o.diag.Counters.TxPackets
		m.PeakPPSInit[i] = o.diag.Counters.PeakPPS
		m.HostPackets[i] = o.host.PacketsSent
		m.PeakPPS1s[i], m.PeakPPS100ms[i] = o.host.PeakPPS1s, o.host.PeakPPS100ms
		m.DistinctPorts[i], m.MaxRun[i] = o.host.DistinctDstPortsPerIP10s, o.host.MaxConsecutiveRun
		m.Filtered[i] = o.filtered
		m.PeerTargets[i], _ = cr.links[i].peerTargets()
		if o.ok() {
			m.Paths[i] = 1 + len(o.sess.Result().ExtraPaths)
		}
	}
	m.ScanBans = r.out[0].scanBans + r.out[1].scanBans
	if cr.sides[0].host == cr.sides[1].host {
		m.ScanBans = r.out[0].scanBans
	}
	if r.resOK {
		m.Outcome = r.res.Outcome.String()
		m.Code = r.res.Code
		m.HalfConfirmed = m.OK && slices.Contains(r.res.Warn, protocol.WarnPeerResultMissing)
		m.Rounds = len(r.res.Rounds)
		for _, rr := range r.res.Rounds {
			m.RoundClasses = append(m.RoundClasses, roundClassName(rr.Class))
			m.MaxClass = maxClass(m.MaxClass, rr.Budget)
		}
		for i := range 2 {
			m.CtlFrames += r.res.Counters.FramesIn[i] + r.res.Counters.FramesOut[i]
		}
		m.Refreshes = r.res.Counters.Refreshes
		if r.res.Winner != nil {
			m.ConfirmRound = r.res.Winner.Round
			m.Family = r.res.Winner.Family
		}
	}
	for i := range 2 {
		for _, rp := range r.out[i].diag.Rounds {
			m.MaxClass = maxClass(m.MaxClass, rp.Budget)
		}
	}
	for _, rp := range r.out[0].diag.Rounds {
		m.Variants = append(m.Variants, rp.Variant)
	}
	if !m.MaxClass.Valid() {
		m.MaxClass = protocol.BudgetLight
	}
	if m.OK {
		if p := cr.links[0].result; p != nil && p.Path != nil {
			m.CandKind = p.Path.CandKind
		}
	}
	if mp := cr.w.measured; mp != nil {
		if v, ok := mp.get(); ok {
			m.Measured = [2]string{describeView(v[0]), describeView(v[1])}
		}
	}
	m.SkewMs, m.FireSkewMs = cr.skew()
	if cr.c.base == classModel {
		m.PModel = cr.pModel()
	}
}

func ms(d time.Duration) float64 { return float64(d) / float64(time.Millisecond) }

func roundClassName(c coord.RoundClass) string {
	switch c {
	case coord.RoundNoReport:
		return "no_report"
	case coord.RoundConfirmed:
		return "confirmed"
	case coord.RoundConfirmLost:
		return "confirm_lost"
	case coord.RoundOneWay:
		return "one_way"
	case coord.RoundNoContact:
		return "no_contact"
	case coord.RoundBlocked:
		return "blocked"
	}
	return fmt.Sprintf("class_%d", c)
}

// skew returns the first-send skew of round 1: the difference
// between the instants the two sides sent their first packet to each other,
// each corrected by the offset its plan prescribes (send_delay_ms and the
// first stage's at_ms), and the fire skew computed from the instants the
// coordinator wrote the two go frames, the links' delays, delay_ms and the
// reported fire_skew_ms. -1 when a side did not fire or the peers share a
// public IP.
func (cr *cellRun) skew() (first, fire float64) {
	first, fire = -1, -1
	pubs := [2][]netip.Addr{cr.sides[0].publicIPs(), cr.sides[1].publicIPs()}
	for _, a := range pubs[0] {
		if slices.Contains(pubs[1], a) {
			return first, fire
		}
	}
	var fires, sends [2]time.Time
	for i := range 2 {
		g := cr.links[i].goOf(1)
		if g == nil {
			return first, fire
		}
		fires[i] = g.at.Add(cr.r.delay[i] + time.Duration(g.msg.DelayMs)*time.Millisecond)
		if rr := cr.links[i].roundResult(1); rr != nil {
			fires[i] = fires[i].Add(time.Duration(rr.FireSkewMs) * time.Millisecond)
		}
	}
	fire = ms(absDur(fires[0].Sub(fires[1])))
	for i := range 2 {
		var to netip.Addr
		for _, a := range pubs[1-i] {
			if at, ok := cr.r.out[i].host.FirstSendTo[a]; ok && (sends[i].IsZero() || at.Before(sends[i])) {
				sends[i], to = at, a
			}
		}
		if sends[i].IsZero() {
			return first, fire
		}
		f := protocol.FamilyUDP4
		if to.Is6() {
			f = protocol.FamilyUDP6
		}
		sends[i] = sends[i].Add(-planOffset(cr.r.out[i].diag.Rounds, f))
	}
	return ms(absDur(sends[0].Sub(sends[1]))), fire
}

// planOffset is when round 1 of a family makes its first initiated send,
// relative to firing.
func planOffset(rounds []protocol.RoundPlan, f protocol.Family) time.Duration {
	if len(rounds) == 0 {
		return 0
	}
	for _, s := range rounds[0].Sides {
		if s.Family != f || len(s.Stages) == 0 {
			continue
		}
		at := s.Stages[0].AtMs
		for _, st := range s.Stages {
			at = min(at, st.AtMs)
		}
		return time.Duration(int(s.SendDelayMs)+int(at)) * time.Millisecond
	}
	return 0
}

func absDur(d time.Duration) time.Duration {
	if d < 0 {
		return -d
	}
	return d
}

// portSpace is the external port range of the simulated NATs (1024–65535).
const portSpace = 65535 - 1024 + 1

// pModel is the birthday model for the run's rounds, from what
// was actually sent: T is a side's round_result distinct_ports, L the
// sockets a hard side actually opened (granted minus bind_failed). One hard
// side: P = 1 − (1 − T_easy/N)^L_hard; two: the product of both sides'
// one-sided P, each with its own L and T; rounds combine as
// 1 − Π(1 − P_k). A cell with plannedModel takes T from the grant
// (max_distinct_ports) instead: the round's success had it run its whole
// window.
func (cr *cellRun) pModel() float64 {
	miss := 1.0
	for k := uint8(1); k <= 8; k++ {
		var t, l [2]float64
		seen := false
		for i := range 2 {
			rr := cr.links[i].roundResult(k)
			if rr == nil {
				continue
			}
			seen = true
			var socks, failed, granted int
			for _, f := range rr.Families {
				t[i] += float64(f.DistinctPorts)
				failed += int(f.BindFailed)
			}
			for _, p := range cr.links[i].plans() {
				if p.Round != k {
					continue
				}
				for _, s := range p.Sides {
					socks += int(s.Sockets)
					granted += int(s.MaxDistinctPorts)
				}
			}
			l[i] = float64(max(socks-failed, 0))
			if cr.c.plannedModel {
				t[i] = float64(granted)
			}
		}
		if !seen {
			continue
		}
		p1 := func(t, l float64) float64 { return 1 - math.Pow(1-t/portSpace, l) }
		var p float64
		switch hard := cr.c.hard; {
		case hard[0] && hard[1]:
			p = p1(t[0], l[0]) * p1(t[1], l[1])
		case hard[0]:
			p = p1(t[1], l[0])
		case hard[1]:
			p = p1(t[0], l[1])
		}
		miss *= 1 - p
	}
	return 1 - miss
}

// classLimits returns the per-round ceiling of the highest class reached.
func (cr *cellRun) classLimits() protocol.ClassLimits {
	l, _ := cr.m.MaxClass.Limits()
	return l
}

// violations runs the per-run assertions of the cell's class
// and the common ones: packet bounds, rate, distinct ports, consecutive
// runs, scan bans, the per-socket packet shape, resources and the cell's own
// checks. Time bounds of the success classes are checked over the runs
// (p95), the others here.
func (cr *cellRun) violations() []string {
	var v []string
	add := func(format string, args ...any) { v = append(v, fmt.Sprintf(format, args...)) }
	c, r, m := cr.c, cr.r, &cr.m

	if !r.done {
		add("the coordinator's session did not end")
	}
	if r.resOK {
		if n := cr.w.resultCalls(r.res.SessionID); n != 1 {
			add("OnResult called %d times", n)
		}
	}
	for i := range 2 {
		if r.out[i].attach != nil {
			add("%s: coord attach: %v", roles[i], r.out[i].attach)
		}
		if r.out[i].inflight != 0 || !r.out[i].rdl.IsZero() || !r.out[i].wdl.IsZero() {
			add("%s: control conn not returned clean: %d reads in flight, read deadline %v, write deadline %v",
				roles[i], r.out[i].inflight, r.out[i].rdl, r.out[i].wdl)
		}
		if n := r.out[i].diag.Counters.LeakedGoroutines; n != 0 {
			add("%s: %d leaked goroutines", roles[i], n)
		}
		if err := r.taps[i].logComplete(); err != nil {
			add("%s: %v", roles[i], err)
		}
	}

	switch c.class {
	case classFail:
		for i := range 2 {
			if m.Reasons[i] != c.want {
				add("%s: reason %q, want %q (%v)", roles[i], m.Reasons[i], c.want, r.out[i].err)
			}
		}
		switch c.fail {
		case failEarly:
			cr.checkEarlyFail(add)
		case failLadder:
			cr.checkLadderFail(add)
		case failVerdict:
			cr.checkVerdict(add)
		}
	default:
		if pb := c.packetBound(); pb > 0 {
			for i := range 2 {
				if m.Packets[i] > pb {
					add("%s: %d initiated packets, bound %d", roles[i], m.Packets[i], pb)
				}
			}
		} else {
			cr.checkModelPackets(add)
		}
		if c.base == classModel {
			cr.checkModelTime(add)
		}
	}

	extreme := cr.w.cfg.extreme
	lim := cr.classLimits()
	for i := range 2 {
		if ppsBound := int(math.Ceil(float64(lim.MaxPPS) * 1.2)); m.PeakPPSInit[i] > ppsBound {
			add("%s: %d initiated packets in one second, class %s allows %d ×1.2", roles[i], m.PeakPPSInit[i], m.MaxClass, lim.MaxPPS)
		}
		if ppsBound := int(math.Ceil(float64(lim.MaxPPS) * 1.2)); m.PeakPPS1s[i] > ppsBound {
			add("%s: host peak %d packets/s, class %s allows %d ×1.2", roles[i], m.PeakPPS1s[i], m.MaxClass, lim.MaxPPS)
		}
		if m.DistinctPorts[i] > int(lim.MaxDistinctPorts) {
			add("%s: %d distinct ports to one IP in 10 s, class %s allows %d", roles[i], m.DistinctPorts[i], m.MaxClass, lim.MaxDistinctPorts)
		}
		if !extreme && m.MaxRun[i] > maxConsecutivePorts {
			add("%s: run of %d consecutive ports, bound %d", roles[i], m.MaxRun[i], maxConsecutivePorts)
		}
	}
	if !extreme && m.ScanBans != 0 {
		add("%d scan bans", m.ScanBans)
	}
	for i := range 2 {
		if i == 1 && cr.sides[1].host == cr.sides[0].host {
			break
		}
		for _, e := range shapeBytes(r.out[i].host.Sockets) {
			add("%s: %s", roles[i], e)
		}
		if !r.spec.ablation.NoOpener {
			for _, e := range shapeOpener(shapeSockets(r.out[i].host.Sockets)) {
				add("%s: %s", roles[i], e)
			}
		}
	}
	if c.check != nil {
		if err := c.check(cr); err != nil {
			add("%v", err)
		}
	}
	return v
}

// sessionBudget is the session budget of the suite's sessions.
func sessionBudget() protocol.Budget { return protocol.DefaultBudget() }

// maxConsecutivePorts bounds a run of consecutive destination ports toward one
// IP. The run is nattest's HostStats.MaxConsecutiveRun, the criterion the
// library's send guard applies too: a repeated port neither extends nor breaks
// a run, a 10 s pause starts a new one.
const maxConsecutivePorts = 3

// verdictRounds and verdictBound are the cheap end of the hopeless SYMRND ×
// SYMRND pair when the summary cannot decide it: the ladder's first two
// rounds, over within 3 s of the first go.
const (
	verdictRounds = 2
	verdictBound  = 3 * time.Second
)

// checkEarlyFail bounds a failure before any punch (no common family, a
// blackholed probe, UDP blocked, and the hopeless SYMRND × SYMRND pair decided
// at summary time): back within probe_timeout + failBound
// of AttachSession, plus the control link's one-way delay that punch_start
// travels; no punch packet of any stage.
func (cr *cellRun) checkEarlyFail(add func(string, ...any)) {
	to := cr.w.cfg.timeouts
	for i := range 2 {
		o := &cr.r.out[i]
		bound := scaled(time.Duration(to.ProbeTimeoutMs)*time.Millisecond + cr.c.failBound + cr.r.delay[i])
		if d := o.dur(); d > bound {
			add("%s: returned after %v, bound %v", roles[i], d, bound)
		}
		st := o.diag.Counters.TxByStage
		if cr.m.Packets[i] != 0 || st["reply"] != 0 || st["handshake"] != 0 {
			add("%s: punch packets sent (%d initiated, stages %v), want none", roles[i], cr.m.Packets[i], st)
		}
	}
}

// checkLadderFail bounds a failure that runs the ladder (a silent peer, two
// homes behind a carrier NAT without hairpin or port mappings): back within
// handshake_timeout + failBound of the first go, plus the
// one-way delay of the link that carries the end, and within the
// session budget.
func (cr *cellRun) checkLadderFail(add func(string, ...any)) {
	to := cr.w.cfg.timeouts
	fg := cr.r.res.Timings.FirstGo
	if fg.IsZero() {
		add("no punch_go; the ladder did not run")
		return
	}
	for i := range 2 {
		bound := scaled(time.Duration(to.HandshakeTimeoutMs)*time.Millisecond + cr.c.failBound + cr.r.delay[i])
		if d := cr.r.out[i].end.Sub(fg); d > bound {
			add("%s: returned %v after the first go, bound %v", roles[i], d, bound)
		}
		if b := sessionBudget(); cr.m.Packets[i] > int(b.MaxPackets) {
			add("%s: %d packets, session budget %d", roles[i], cr.m.Packets[i], b.MaxPackets)
		}
	}
}

// checkVerdict judges the hopeless SYMRND × SYMRND pair.
// When natprobe measured both sides' port allocation as Random with High
// confidence the coordinator ends the session at summary time: no punch
// packet, as an early failure. Otherwise the ladder's two cheap rounds run
// and end it: at most two rounds, each side's initiated packets within the
// grants of those rounds (plus two per pushed peer target, which have
// their own quota), back within 3 s of the first go plus the link's
// one-way delay.
func (cr *cellRun) checkVerdict(add func(string, ...any)) {
	measured, ok := cr.w.measured.get()
	if !ok {
		add("the session was never classified")
		return
	}
	res := cr.r.res
	if randomHigh(measured[0]) && randomHigh(measured[1]) {
		if !res.Timings.FirstGo.IsZero() {
			add("natprobe measured %q and %q, yet the ladder ran (%d rounds)", cr.m.Measured[0], cr.m.Measured[1], len(res.Rounds))
		}
		cr.checkEarlyFail(add)
		return
	}
	fg := res.Timings.FirstGo
	if fg.IsZero() {
		add("ended at summary time, but natprobe measured %q and %q (the summary-time verdict needs High Random on both sides)", cr.m.Measured[0], cr.m.Measured[1])
		return
	}
	if len(res.Rounds) > verdictRounds {
		add("%d rounds, want the %d cheap ones", len(res.Rounds), verdictRounds)
	}
	for i := range 2 {
		granted := 0
		for _, rr := range res.Rounds[:min(len(res.Rounds), verdictRounds)] {
			granted += rr.Granted[i]
		}
		if bound := granted + 2*cr.m.PeerTargets[i]; cr.m.Packets[i] > bound {
			add("%s: %d initiated packets, grants of the first two rounds %d + %d peer targets ×2", roles[i], cr.m.Packets[i], granted, cr.m.PeerTargets[i])
		}
		bound := scaled(verdictBound + cr.r.delay[i])
		if d := cr.r.out[i].end.Sub(fg); d > bound {
			add("%s: returned %v after the first go, bound %v", roles[i], d, bound)
		}
	}
}

// checkModelTime: a model cell that fails must return within handshake +
// 1 s of the first go with hard_symmetric_random, packet_budget_exceeded or
// candidate_timeout. The handshake is the session's, from its
// punch_start: a Background session has a longer one.
func (cr *cellRun) checkModelTime(add func(string, ...any)) {
	if cr.m.OK {
		return
	}
	to := cr.w.cfg.timeouts
	if st := cr.links[0].start; st != nil {
		to.HandshakeTimeoutMs = st.Timeouts.HandshakeTimeoutMs
	}
	for i := range 2 {
		o := &cr.r.out[i]
		switch o.reason() {
		case protocol.ReasonHardSymmetricRandom, protocol.ReasonPacketBudgetExceeded, protocol.ReasonCandidateTimeout,
			protocol.ReasonOneWayUDPOnly: // a PDF×RND pair whose one direction works
		default:
			add("%s: model failure reason %q (%v)", roles[i], o.reason(), o.err)
		}
		if fg := cr.r.res.Timings.FirstGo; !fg.IsZero() {
			bound := scaled(time.Duration(to.HandshakeTimeoutMs)*time.Millisecond + time.Second + cr.r.delay[i])
			if d := o.end.Sub(fg); d > bound {
				add("%s: returned %v after the first go, bound %v", roles[i], d, bound)
			}
		}
	}
}

// checkModelPackets: the initiated packets of a side stay within the
// grants of its rounds × 1.1 plus two per pushed peer target, and within
// the session budget.
func (cr *cellRun) checkModelPackets(add func(string, ...any)) {
	r := cr.r
	for i := range 2 {
		granted := 0
		if r.resOK {
			for _, rr := range r.res.Rounds {
				granted += rr.Granted[i]
			}
		}
		bound := int(math.Floor(float64(granted)*1.1)) + 2*cr.m.PeerTargets[i]
		if cr.m.Packets[i] > bound {
			add("%s: %d initiated packets, grants %d ×1.1 + %d peer targets ×2 = %d", roles[i], cr.m.Packets[i], granted, cr.m.PeerTargets[i], bound)
		}
		limit := sessionBudget().MaxPackets
		if p := cr.w.cfg.policy; p != nil && p.Budget.MaxPackets > 0 {
			limit = p.Budget.MaxPackets
		}
		if cr.m.Packets[i] > int(limit) {
			add("%s: %d initiated packets, session budget %d", roles[i], cr.m.Packets[i], limit)
		}
	}
}

// Packet-shape purposes: the sockets of a session whose packets the shape
// checks cover (portmap requests excluded).
var shapePurposes = []string{holepunch.PurposeProbe, holepunch.PurposeSibling, holepunch.PurposeWarmup, holepunch.PurposeBirthday,
	holepunch.PurposeFresh}

// Shape thresholds: ConstantOffsets is asserted on sockets with at least
// minShapePackets packets (a random byte repeats over k packets with
// probability 256^-(k-1)); the first-byte histogram must not reject
// uniformity at chi2Limit (11 degrees of freedom, p ≈ 1e-6) once there are
// minUniformPackets packets.
const (
	minShapePackets   = 8
	minUniformPackets = 120
	chi2Limit         = 50.0
)

// shapeSockets returns the sockets of the shape purposes.
func shapeSockets(socks []nattest.SocketStats) []nattest.SocketStats {
	var out []nattest.SocketStats
	for _, s := range socks {
		if slices.Contains(shapePurposes, s.Purpose) {
			out = append(out, s)
		}
	}
	return out
}

// shapeBytes checks the packet bytes per socket: every first byte in
// [B0Min, B0Max], close to uniform over the session's sockets, and no
// payload offset constant within a socket of at least eight packets. The
// STUN openers are left out of all three (nattest.SocketStats):
// their header bytes are the STUN standard's; shapeOpener checks them.
func shapeBytes(socks []nattest.SocketStats) []string {
	var out []string
	var hist [256]uint64
	for _, s := range socks {
		if !slices.Contains(shapePurposes, s.Purpose) {
			continue
		}
		for b, n := range s.FirstByteHistogram {
			hist[b] += n
			if n > 0 && (b < udpwire.B0Min || b > udpwire.B0Max) {
				out = append(out, fmt.Sprintf("socket %v (%s): %d packets with first byte %#x outside [%#x, %#x]",
					s.Local, s.Purpose, n, b, udpwire.B0Min, udpwire.B0Max))
			}
		}
		if s.PacketsSent-s.STUNPackets >= minShapePackets && len(s.ConstantOffsets) > 0 {
			out = append(out, fmt.Sprintf("socket %v (%s): constant bytes at offsets %v over %d packets",
				s.Local, s.Purpose, s.ConstantOffsets, s.PacketsSent))
		}
	}
	var total uint64
	for b := udpwire.B0Min; b <= udpwire.B0Max; b++ {
		total += hist[b]
	}
	if total >= minUniformPackets {
		k := float64(udpwire.B0Max - udpwire.B0Min + 1)
		exp := float64(total) / k
		chi2 := 0.0
		for b := udpwire.B0Min; b <= udpwire.B0Max; b++ {
			d := float64(hist[b]) - exp
			chi2 += d * d / exp
		}
		if chi2 > chi2Limit {
			out = append(out, fmt.Sprintf("first bytes not uniform: chi2 %.1f over %d packets", chi2, total))
		}
	}
	return out
}

// errNotSucceeded marks a check that needs a success.
var errNotSucceeded = errors.New("session did not succeed")
