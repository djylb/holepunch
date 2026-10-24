package holepunch

import (
	"errors"
	"net"
	"net/netip"
	"slices"
	"time"

	"github.com/djylb/holepunch/internal/candidate"
	"github.com/djylb/holepunch/internal/controlwire"
	"github.com/djylb/holepunch/internal/faultinject"
	"github.com/djylb/holepunch/internal/life"
	"github.com/djylb/holepunch/internal/trunc"
	"github.com/djylb/holepunch/protocol"
)

// Cleanup bounds.
const (
	resultFlush = 200 * time.Millisecond
	joinBound   = life.JoinTimeout
)

// Fault-injection points of the cleanup.
const (
	fiFinalizeDisown = "finalize.disown"
	fiResultWrite    = "result.write"
)

var errFinishing = errors.New("holepunch: session finishing")

// finish is the single exit of Punch, for success and failure alike.
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
		rt.step("finish.classify", func() { f = classify(rt.callerCtx, cause) }, &f)
		if f == nil { // no winner is a failure, whatever classify made of the cause
			f = fail(protocol.ReasonInternal, "no_outcome", cause)
		}
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
	switch {
	case f != nil:
		rt.phases.advance(protocol.PhaseFailed, string(f.reason), now)
	case win != nil: // no failure means a winner: classify never returns nil
		rt.primaryPath, rt.extraPaths = rt.confirmedPaths(win, ho)
		rt.timing.handover = now.Sub(rt.punch.confirmTime())
		rt.phases.advance(protocol.PhaseDone, stageHandoverDone, now)
		rt.progress(progressEvent{stage: stageHandoverDone, status: protocol.StatusOK, detail: string(win.ConfirmedBy), family: win.Family, remote: win.Remote})
	}
	rt.timing.total = now.Sub(rt.attachAt)
	// 5
	if rt.started {
		rt.step("finish.result", func() { rt.writeResult(f, failPhase) }, &f)
		rt.step("finish.release", func() {
			if err := rt.ctl.conn.Release(); errors.Is(err, controlwire.ErrUnreturnable) {
				rt.addWarn(protocol.WarnControlUnreturnable)
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
	if rt.sink != nil {
		rt.sink.closed.Store(true) // a delivery the join gave up on calls OnProgress no more
	}
	if rt.deadline != nil {
		rt.deadline.Stop()
	}
	// 7
	if f != nil || win == nil { // win is nil only with a failure (see above)
		var diag *Diagnostics
		if rt.started {
			d := rt.diagnostics(win, f, failPhase)
			diag = &d
		}
		e := rt.newError(f, failPhase, diag)
		rt.logFailure(e)
		return nil, e
	}
	sess := rt.session(win, ho, rt.diagnostics(win, nil, failPhase))
	rt.logDone(sess)
	return sess, nil
}

// session builds the Session of a successful handover: the paths' distinct
// sockets, the primary path's first, the port mappings to release first on
// Close, and the codec of the residual filter, bound to every confirmed
// remote.
func (rt *runtime) session(win *candidate.Action, ho *handoff, diag Diagnostics) *Session {
	s := &Session{diag: diag, conns: []net.PacketConn{ho.primary.s.sock.conn}, codec: rt.codec}
	peers := []netip.AddrPort{win.Remote}
	res := rt.result(ho.primary)
	for i, p := range ho.paths() {
		if !slices.ContainsFunc(s.conns, func(c net.PacketConn) bool { return sameConn(c, p.s.sock.conn) }) {
			s.conns = append(s.conns, p.s.sock.conn)
		}
		peers = append(peers, p.c.Remote)
		info := rt.pathInfo(p.c, win.Epoch) // what confirmedPaths reported, recomputed when it did not run
		if i < len(rt.extraPaths) {
			info = rt.extraPaths[i]
		}
		res.ExtraPaths = append(res.ExtraPaths, rt.path(info, p))
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

// newError builds the *Error of a failure.
func (rt *runtime) newError(f *failure, phase Phase, diag *Diagnostics) *Error {
	e := &Error{
		Reason: f.reason, Phase: phase, LastEvent: rt.phases.lastEvent(), AbortedBy: f.abortedBy,
		Detail: trunc.String(f.detail, protocol.MaxDetail), RetryAfter: f.retryAfter, Advice: rt.summary.Plan.Advice, Diagnostics: diag, Err: f.err,
	}
	if !rt.firstGoAt.IsZero() {
		e.Round = int(rt.currentRound())
	}
	return e
}
