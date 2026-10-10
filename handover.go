package holepunch

import (
	"errors"
	"net/netip"
	"slices"
	"time"

	"github.com/djylb/holepunch/controlwire"
	"github.com/djylb/holepunch/internal/candidate"
	"github.com/djylb/holepunch/internal/faultinject"
	"github.com/djylb/holepunch/internal/life"
	"github.com/djylb/holepunch/internal/nat"
	"github.com/djylb/holepunch/internal/plan"
	"github.com/djylb/holepunch/protocol"
	"github.com/djylb/holepunch/udpwire"
)

// Cleanup bounds.
const (
	resultFlush = 200 * time.Millisecond
	joinBound   = life.JoinTimeout
	maxWarn     = 8
)

// Fault-injection points of the cleanup.
const (
	fiFinalizeDisown = "finalize.disown"
	fiResultWrite    = "result.write"
)

// Warnings beyond the protocol's list (warn is an open enumeration).
const (
	// warnControlUnreturnable: controlwire could not hand the control
	// connection back at a frame boundary; the caller must close it.
	warnControlUnreturnable = "control_unreturnable"
	// warnAbortAfterConfirm: a punch_abort arrived after the local Confirm
	// and was ignored.
	warnAbortAfterConfirm = "abort_after_confirm"
	// warnControlLostAfterConfirm: the control link ended after the local
	// Confirm; the handover went on over UDP.
	warnControlLostAfterConfirm = "control_lost_after_confirm"
)

var errFinishing = errors.New("holepunch: session finishing")

// onConfirm runs on the nomination goroutine at the local Confirm:
// initiation stops at once on every family and socket, control
// faults become harmless, and the orchestrator is woken to write
// round_result{confirmed} and to arm the handover timeout.
func (rt *runtime) onConfirm(a candidate.Action, at time.Time) {
	rt.sender.stop()
	rt.ctl.confirm()
	st := rt.punch
	c, _ := rt.nom.mgr.Winner()
	path := rt.pathInfo(c, a.Epoch)
	st.mu.Lock()
	st.confirmAt, st.confirmPath = at, path
	st.mu.Unlock()
	st.confirmed.Store(true)
	rt.phases.advanceFamily(a.Family, protocol.PhaseConfirmed, stageConfirmed, at)
	rt.phases.advance(protocol.PhaseHandover, "handover_started", at)
	rt.progress(progressEvent{stage: stageConfirmed, status: protocol.StatusOK, family: a.Family, round: path.Round, remote: a.Remote})
	st.notify()
}

// pathInfo describes the confirmed pair c, of the campaign at epoch, for
// round_result, punch_result and Diagnostics.
func (rt *runtime) pathInfo(c candidate.Candidate, epoch uint16) protocol.PathInfo {
	p := protocol.PathInfo{
		Family: c.Family, Local: c.Local, Remote: c.Remote, Round: rt.currentRound(), Epoch: epoch,
		Cand: udpwire.NoCand, CandKind: c.CandKind(), Kind: rt.pathKind(c.Family, c.Remote, c.Kind),
		RTTMs: uint16(min(c.MinRTT/time.Millisecond, 0xFFFF)),
	}
	if s := rt.socks.byAddr(c.Local); s != nil {
		p.Sock = s.id
	}
	st := rt.punch
	st.mu.Lock()
	defer st.mu.Unlock()
	for k, to := range st.cands {
		if to == c.Remote && k.sock == p.Sock {
			p.Cand = k.cand
			break
		}
	}
	return p
}

// extraPathInfos describes the extra paths handed over with win, confirmed
// by the same evidence.
func (rt *runtime) extraPathInfos(win *candidate.Action, paths []handPath) []protocol.PathInfo {
	var out []protocol.PathInfo
	for _, hp := range paths {
		p := rt.pathInfo(hp.c, win.Epoch)
		p.ConfirmedBy = win.ConfirmedBy
		out = append(out, p)
	}
	return out
}

// onHandOver records the handover decision with the committed extra paths
// and wakes the orchestrator.
func (rt *runtime) onHandOver(a candidate.Action, extras []candidate.Candidate) {
	st := rt.punch
	st.mu.Lock()
	if st.handedOver == nil {
		st.handedOver, st.extras = &a, extras
	}
	st.mu.Unlock()
	st.notify()
}

// onHandoverFailed records the handover timeout as the state machine saw it.
func (rt *runtime) onHandoverFailed() {
	st := rt.punch
	st.mu.Lock()
	st.failed = true
	st.mu.Unlock()
	st.notify()
}

func (st *punchState) confirmTime() time.Time {
	st.mu.Lock()
	defer st.mu.Unlock()
	return st.confirmAt
}

func (st *punchState) path() protocol.PathInfo {
	st.mu.Lock()
	defer st.mu.Unlock()
	return st.confirmPath
}

// committedExtras returns the extra paths committed with the handover.
func (st *punchState) committedExtras() []candidate.Candidate {
	st.mu.Lock()
	defer st.mu.Unlock()
	return st.extras
}

// outcome returns the handover decision, or whether the handover failed.
func (st *punchState) outcome() (*candidate.Action, bool) {
	st.mu.Lock()
	defer st.mu.Unlock()
	return st.handedOver, st.failed
}

// attribute explains an unconfirmed end of punching from this side's
// evidence.
func (rt *runtime) attribute() *failure {
	st := rt.punch
	_, _, pct := rt.sender.usage()
	ev := punchEvidence{
		role: rt.role, rxVerified: int(st.rx.Load()), sent: rt.sentTotal(), fired: rt.fired,
		budgetUsedPct: pct, udpBlocked: rt.udpBlocked.Load(), birthdayRan: rt.birthdayRan,
	}
	st.mu.Lock()
	ev.hit, ev.seenFrom, ev.peerSeenUs, ev.icmpUnreach = st.anyHit, len(st.seenSrc), st.peerSeen, st.icmpMax
	st.mu.Unlock()
	for _, w := range rt.workers {
		ev.tokenMismatch += int(w.fs.cnt.tokenMismatch.Load())
		if plan.CategoryOf(w.selfTraits) == plan.CatRND && plan.CategoryOf(w.peerTraits) == plan.CatRND {
			ev.bothRND = true
		}
	}
	r, d := attributePunch(ev)
	return fail(r, d, nil)
}

// sentTotal is the number of initiated packets of the session.
func (rt *runtime) sentTotal() int {
	n := 0
	for _, fs := range rt.fams {
		n += int(fs.cnt.tx.Load())
	}
	return n
}

// finish is the single exit of AttachSession, for success and failure alike.
// Every step runs in a recover boundary so a panic in one never skips the next.
// On success it hands over the sockets of every confirmed path: the primary
// path's and those of the extra paths, each once.
//
//  1. Disown the sockets and their port mappings from the session group and
//     detach them from the sender: the library never writes them again.
//  2. Cancel punching and interrupt the sockets' read loops.
//  3. Join those loops (within winnerReadJoin, else
//     internal/readloop_stuck and the sockets are closed) and every punching
//     goroutine.
//  4. Clear the sockets' deadlines and restore their TTL: the last touch.
//  5. Queue punch_result, flush it for at most 200 ms, release the control
//     connection.
//  6. Close the session group: every other socket and mapping, every other
//     goroutine.
//  7. Return the Session or the Error.
//
// A failure skips steps 1 and 4. A failure after step 1 — in its own steps
// up to step 5 — closes the disowned sockets and their port mappings instead
// of handing them out: nothing else would ever close them. An extra path's
// socket that fails step 1 or 3 is closed and that path dropped; the session
// goes on with the others.
func (rt *runtime) finish(win *candidate.Action, cause error) (*Session, error) {
	var f *failure
	var ho *handoff
	failPhase := rt.phases.current()
	switch {
	case win != nil && rt.callerCtx.Err() != nil:
		f = fail(protocol.ReasonCanceled, "", rt.callerCtx.Err())
	case win != nil:
		if ho = rt.handoffOf(win); ho == nil {
			f = fail(protocol.ReasonInternal, "winner_missing", nil)
		}
	default:
		f = classify(rt.callerCtx, cause)
	}

	// 1
	if f == nil {
		rt.step("finish.disown", func() {
			if err := faultinject.Point(fiFinalizeDisown); err != nil {
				f = fail(protocol.ReasonInternal, "disown", err)
				return
			}
			f = rt.disown(ho)
		}, &f)
	}
	// 2
	if rt.pg != nil {
		rt.pg.Fail(errFinishing)
	}
	if f == nil {
		ho.stopReads(rt, &f)
	}
	// 3
	if f == nil {
		f = rt.joinReads(ho)
	}
	if rt.pg != nil {
		rt.step("finish.joinpunch", func() { _ = rt.pg.Close(joinBound) }, &f)
	}
	if f != nil && ho != nil {
		rt.closeAll(ho)
	}
	// 4
	if f == nil {
		ho.restore(rt, &f)
	}
	now := rt.clk.Now()
	if f == nil {
		rt.extraPaths = rt.extraPathInfos(win, ho.paths())
		rt.timing.handover = now.Sub(rt.punch.confirmTime())
		rt.phases.advance(protocol.PhaseDone, stageHandoverDone, now)
		rt.progress(progressEvent{stage: stageHandoverDone, status: protocol.StatusOK, detail: string(win.ConfirmedBy), family: win.Family, remote: win.Remote})
	} else {
		rt.phases.advance(protocol.PhaseFailed, string(f.reason), now)
	}
	rt.timing.total = now.Sub(rt.attachAt)
	// 5
	if rt.started {
		rt.step("finish.result", func() { rt.writeResult(win, f, failPhase) }, &f)
		rt.step("finish.release", func() {
			if err := rt.ctl.conn.Release(); errors.Is(err, controlwire.ErrUnreturnable) {
				rt.addWarn(warnControlUnreturnable)
			}
		}, &f)
	} else {
		rt.step("finish.release", func() { _ = rt.ctl.conn.Release() }, &f)
	}
	if f != nil && ho != nil { // steps 4 and 5 can still fail
		rt.closeAll(ho)
	}
	// 6
	_ = rt.g.Close(joinBound)
	if rt.deadline != nil {
		rt.deadline.Stop()
	}
	// 7
	if f != nil {
		var diag *Diagnostics
		if rt.started {
			d := rt.diagnostics(win, f, failPhase)
			diag = &d
		}
		return nil, rt.newError(f, failPhase, diag)
	}
	return rt.session(win, ho, rt.diagnostics(win, nil, failPhase)), nil
}

// session builds the Session of a successful handover: the primary path's
// socket, the extra paths' in the order of Result.ExtraPaths, the port
// mappings to release first on Close, and the residual filter bound to
// every confirmed remote.
func (rt *runtime) session(win *candidate.Action, ho *handoff, diag Diagnostics) *Session {
	primary := ho.socks[0]
	s := &Session{diag: diag, conn: primary.sock.conn, residual: ResidualFilter{Codec: rt.codec, Window: udpwire.DefaultResidualWindow}}
	peers := []netip.AddrPort{win.Remote}
	res := rt.result(win, primary)
	for _, p := range ho.paths() {
		s.extra = append(s.extra, p.s.sock.conn)
		peers = append(peers, p.c.Remote)
		res.ExtraPaths = append(res.ExtraPaths, rt.path(p.c, p.s))
	}
	for _, hs := range ho.socks {
		if !hs.lost && hs.mapping != nil {
			s.releases = append(s.releases, hs.mapping.Close)
		}
	}
	s.result = res
	rt.codec.BindPeers(peers...)
	return s
}

// step runs one cleanup step in a recover boundary; a panic becomes the
// session's failure if it had none, and the cleanup goes on.
func (rt *runtime) step(name string, fn func(), f **failure) {
	if pe := life.Safe(name, fn); pe != nil {
		rt.cnt.callbackPanics.Add(1)
		if *f == nil {
			*f = fail(protocol.ReasonInternal, "panic:"+name, pe)
		}
	}
}

// writeResult queues punch_result and flushes it for at most 200 ms.
// A control_version_mismatch writes nothing.
func (rt *runtime) writeResult(win *candidate.Action, f *failure, failPhase Phase) {
	if f != nil && f.reason == protocol.ReasonControlVersionMismatch {
		return
	}
	if dead, _ := rt.ctl.dead(); dead || faultinject.Point(fiResultWrite) != nil {
		return
	}
	pr := protocol.PunchResult{
		SessionID: rt.start.SessionID, Role: rt.role, OK: f == nil, Phase: protocol.PhaseDone,
		Stats: rt.wireStats(), Timing: rt.wireTiming(), Traits: rt.corrections(), Warn: rt.warnings(),
	}
	if f != nil {
		pr.Code, pr.Phase, pr.Detail = f.reason, failPhase, truncDetail(f.detail)
	} else {
		p := rt.punch.path()
		p.ConfirmedBy = win.ConfirmedBy
		pr.Path, pr.ExtraPaths = &p, rt.extraPaths
	}
	if rt.ctl.send(pr) == nil {
		rt.ctl.flush(resultFlush)
	}
}

func (rt *runtime) wireStats() protocol.Stats {
	c := rt.counters()
	s := protocol.Stats{Sent: uint32(c.TxPackets), Recv: uint32(c.RxVerified), Replies: uint32(c.TxByStage[txStageNames[txReply]]),
		Rounds: uint8(min(len(rt.roundsRun), 255)), Drops: map[string]uint32{}}
	for k, v := range c.Drops {
		s.Drops[k] = uint32(v)
	}
	st := rt.punch
	st.mu.Lock()
	hits := len(st.hit)
	st.mu.Unlock()
	s.Hits = uint8(min(hits, 255))
	_, _, pct := rt.sender.usage()
	s.BudgetHit = pct >= 100
	return s
}

func (rt *runtime) wireTiming() protocol.Timing {
	ms := func(d time.Duration) uint32 { return uint32(max(d, 0) / time.Millisecond) }
	t := rt.publicTiming()
	return protocol.Timing{ProbeMs: ms(t.Probe), SummaryWaitMs: ms(t.SummaryWait), GoWaitMs: ms(t.GoWait), PunchMs: ms(t.Punch), HandoverMs: ms(t.Handover)}
}

func (rt *runtime) publicTiming() Timing {
	t := Timing{Probe: rt.timing.probe, SummaryWait: rt.timing.summaryWait, GoWait: rt.timing.goWait,
		Handover: rt.timing.handover, Total: rt.timing.total}
	if !rt.firstGoAt.IsZero() {
		end := rt.clk.Now()
		if rt.punch.confirmed.Load() {
			end = rt.punch.confirmTime()
		}
		t.Punch = end.Sub(rt.firstGoAt)
	}
	return t
}

// corrections are the punch-time corrections of this side's traits
// (punch_result.traits): the table reclassified with the peer_seen and
// hairpin evidence, against the summary's view.
func (rt *runtime) corrections() []protocol.TraitsUpdate {
	var out []protocol.TraitsUpdate
	for _, w := range rt.workers {
		tab := w.fs.table()
		if tab == nil {
			continue
		}
		src := protocol.TraitsSourceHairpin
		if rt.traitsSource[famIndex(w.fam)].Load() {
			src = protocol.TraitsSourcePeer
		}
		if u, ok := nat.Correction(w.selfTraits, tab.Classify(), src); ok {
			u.Family = w.fam
			out = append(out, u)
		}
	}
	if len(out) > 0 {
		rt.progress(progressEvent{stage: stageTraitsCorrected, status: protocol.StatusInfo})
	}
	return out
}

// counters is the session total.
func (rt *runtime) counters() Counters {
	var parts []Counters
	for _, fs := range rt.fams {
		parts = append(parts, fs.cnt.snapshot())
	}
	c := sumCounters(parts...)
	if rt.sender != nil {
		c.DistinctTargets, c.PeakPPS, c.BudgetUsedPct = rt.sender.usage()
	}
	cs := rt.ctl.conn.Stats()
	c.ControlFramesIn, c.ControlFramesOut = int(cs.FramesIn), int(cs.FramesOut)
	c.ProgressDropped = int(rt.cnt.progressDropped.Load())
	c.CallbackPanics = int(rt.cnt.callbackPanics.Load())
	c.LeakedGoroutines = rt.g.Stats().Leaked
	if rt.pg != nil {
		c.LeakedGoroutines += rt.pg.Stats().Leaked
	}
	return c
}

// diagnostics assembles the session's Diagnostics. A session that failed
// before punch_start was read has none; finish does not call it then.
func (rt *runtime) diagnostics(win *candidate.Action, f *failure, failPhase Phase) Diagnostics {
	phase, timeline, last := rt.phases.snapshot()
	d := Diagnostics{
		SessionID: rt.start.SessionID, Role: rt.role, Phase: phase, LastEvent: last, Timeline: timeline,
		Counters: rt.counters(), Timing: rt.publicTiming(), RTT: rt.lastRTT,
	}
	if rt.counters().LeakedGoroutines > 0 {
		rt.addWarn(protocol.WarnGoroutineJoinTimeout)
	}
	d.Warn = rt.warnings()
	if f != nil {
		d.Reason, d.Phase = f.reason, failPhase
	}
	if rt.summaryAt.IsZero() {
		return d
	}
	p := clonePlan(rt.summary.Plan)
	d.Plan = &p
	for _, r := range rt.roundsRun {
		d.Rounds = append(d.Rounds, cloneRound(r))
	}
	for _, w := range rt.workers {
		self := w.selfTraits
		if tab := w.fs.table(); tab != nil {
			if _, ok := nat.Correction(w.selfTraits, tab.Classify(), protocol.TraitsSourcePeer); ok {
				self = tab.Classify()
			}
		}
		d.Self = append(d.Self, self)
		d.Peer = append(d.Peer, w.peerTraits)
		fd := FamilyDiagnostics{Family: w.fam, Strategy: rt.strategy(w), Counters: w.fs.cnt.snapshot(),
			Candidates: rt.nom.candidates(w.fam, rt.punch.planned(w.fam)), Hints: familyHints(self, w.peerTraits)}
		if win != nil && f == nil {
			fd.Confirmed = confirmedRemote(win, rt.extraPaths, w.fam)
		}
		d.Families = append(d.Families, fd)
	}
	if win != nil && f == nil {
		p := rt.punch.path()
		p.ConfirmedBy = win.ConfirmedBy
		d.Path, d.ExtraPaths = &p, slices.Clone(rt.extraPaths)
	}
	return d
}

// confirmedRemote is the confirmed remote of family f: the primary path's
// when it is of f, else the first extra path's of f.
func confirmedRemote(win *candidate.Action, extra []protocol.PathInfo, f protocol.Family) netip.AddrPort {
	if win.Family == f {
		return win.Remote
	}
	for _, p := range extra {
		if p.Family == f {
			return p.Remote
		}
	}
	return netip.AddrPort{}
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

// strategy is the diagnostic name "<pair_class>/<last variant>".
func (rt *runtime) strategy(w *worker) string {
	s := rt.summary.Plan.PairClass
	for i := len(rt.roundsRun) - 1; i >= 0; i-- {
		r := rt.roundsRun[i]
		if hasSide(r, w.fam) {
			s += "/" + r.Variant
			break
		}
	}
	if w.lowTTLOff.Load() || !w.lowTTL {
		s += ";lowttl=unavailable"
	}
	return s
}

func hasSide(r protocol.RoundPlan, f protocol.Family) bool {
	for _, s := range r.Sides {
		if s.Family == f {
			return true
		}
	}
	return false
}

// result builds Result for the primary path on primary; session adds the
// extra paths.
func (rt *runtime) result(win *candidate.Action, primary *handSock) Result {
	path := rt.punch.path()
	r := Result{
		SessionID: rt.start.SessionID, Role: rt.role,
		Path:          rt.newPath(win.Family, path.Kind, primary.sock.local, win.Remote, time.Duration(path.RTTMs)*time.Millisecond, primary.info),
		TransportMode: rt.transport.Mode, TransportData: rt.transport.PeerData,
		TransportTimeout: time.Duration(rt.timeouts.TransportTimeoutMs) * time.Millisecond,
		Rounds:           len(rt.roundsRun), Timing: rt.publicTiming(),
	}
	for _, rp := range rt.roundsRun {
		if rp.Round == path.Round {
			r.Variant = rp.Variant
		}
	}
	return r
}

// path describes the extra path c on hs for Result.ExtraPaths.
func (rt *runtime) path(c candidate.Candidate, hs *handSock) Path {
	return rt.newPath(c.Family, rt.pathKind(c.Family, c.Remote, c.Kind), hs.sock.local, c.Remote, c.MinRTT, hs.info)
}

// newPath is a Path with the keepalive its kind of network, the traits of
// its family and its socket's port mapping call for.
func (rt *runtime) newPath(fam protocol.Family, kind protocol.PathKind, local, remote netip.AddrPort, rtt time.Duration, pm *protocol.PortMappingInfo) Path {
	var self, peer protocol.Traits
	if w := rt.fam(fam).worker; w != nil {
		self, peer = w.selfTraits, w.peerTraits
	}
	return Path{Family: fam, Kind: kind, LocalAddr: local, RemoteAddr: remote, RTT: rtt,
		Keepalive: keepaliveFor(fam, kind, self, peer, pm), PortMapping: pm}
}

// newError builds the *Error of a failure.
func (rt *runtime) newError(f *failure, phase Phase, diag *Diagnostics) *Error {
	e := &Error{
		Reason: f.reason, Phase: phase, LastEvent: rt.phases.lastEvent(), AbortedBy: f.abortedBy,
		Detail: truncDetail(f.detail), RetryAfter: f.retryAfter, Advice: rt.summary.Plan.Advice, Diagnostics: diag, Err: f.err,
	}
	if !rt.firstGoAt.IsZero() {
		e.Round = int(rt.currentRound())
	}
	return e
}

// table is the family's observation table, once probing produced one.
func (f *famState) table() *nat.ObsTable {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.result.Table
}

// addWarn records a warning once (at most eight are kept).
func (rt *runtime) addWarn(w string) {
	rt.warnMu.Lock()
	defer rt.warnMu.Unlock()
	for _, x := range rt.warn {
		if x == w {
			return
		}
	}
	if len(rt.warn) < maxWarn {
		rt.warn = append(rt.warn, w)
	}
}

func (rt *runtime) warnings() []string {
	rt.warnMu.Lock()
	defer rt.warnMu.Unlock()
	return append([]string(nil), rt.warn...)
}
