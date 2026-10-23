package holepunch

import (
	"context"
	"errors"
	"net/netip"
	"slices"
	"sync/atomic"
	"time"

	"github.com/djylb/holepunch/internal/candidate"
	"github.com/djylb/holepunch/internal/faultinject"
	"github.com/djylb/holepunch/internal/nat"
	"github.com/djylb/holepunch/internal/netaddr"
	"github.com/djylb/holepunch/internal/plan"
	"github.com/djylb/holepunch/internal/udpwire"
	"github.com/djylb/holepunch/protocol"
)

// One family's side of a round: the round goroutine and its sockets.

// sendItem is one initiated packet of a round's schedule.
type sendItem struct {
	due   time.Time
	sock  *udpSock
	to    netip.AddrPort
	cand  uint16
	stage txStage
	hops  int
	quota sendQuota // quotaPlan or quotaTargets
	// slot is a paced socket of the round (FamilySide.OpenPerSec), opened
	// when its first item is due; sock is nil until then. 0 for none.
	slot int
}

// extraTarget is a target pushed by peer_targets: sent at once
// from the primary socket, protocol.PushPackets times, on the round's peer_targets
// quota. window marks a port of the assist's port window, which the
// round sends in the order of its spray seed (scatterWindows).
type extraTarget struct {
	to     netip.AddrPort
	kind   candidate.Kind
	window bool
}

// familyRound executes one family's side of a round.
type familyRound struct {
	rt         *runtime
	run        *roundRun
	w          *worker
	side       protocol.FamilySide
	meter      *roundMeter
	socks      []*udpSock
	bindFailed int
	// lateFailed counts the round's sockets the round goroutine could not
	// bind — fresh and paced ones — while round_result may
	// be built, so it is atomic.
	lateFailed atomic.Int32
	// paced are the round's paced sockets by slot (OpenPerSec),
	// opened by the round goroutine; tried marks the slots it attempted.
	// Only that goroutine touches them.
	paced, owned []*udpSock
	tried        []bool
	bindRun      int         // consecutive paced bind failures
	writeFails   []time.Time // recent send failures of a background round
	halted       atomic.Bool // stopped initiating on a failure spike (round_result.halted)
	seed         [8]byte
	inject       chan []extraTarget
	extras       atomic.Int32 // peer_targets targets scheduled this round
	rejected     atomic.Int32 // targets admission refused this round (round_result.rejected)
	budgetSaid   atomic.Bool
}

// execute is a family's round goroutine: it builds the round's schedule —
// direct stages on every round socket, predict and random targets spread over
// them — waits for the fire instant and sends through the gate until the
// round is stopped. Direct packets keep their offsets; spraying fills the
// gaps at the rate the buckets allow. Once a valid peer packet arrived,
// spraying stops and only answered targets get more packets. A grant spent
// ends the planned stages (budget_hit) but not the round: pushed targets
// have their own quota and are still sent. A packet the run guard
// holds back (runs.go) waits until another packet has left, which breaks or
// moves the run, and is then tried again before anything else: it is
// overdue, and the next packet may close the gap it needs.
func (fr *familyRound) execute(_ context.Context) {
	defer fr.run.exited()
	ctx := fr.run.ctx // derived from the punching group's: canceled by the round's end too
	rt := fr.rt
	if err := faultinject.Point(fiRoundStage); err != nil {
		return
	}
	// Fresh sockets are bound before the fire time, paced ones while the
	// round runs; both are released when the round ends, unless the peer
	// reached one: its pairs are candidates.
	fresh := fr.bindFresh(ctx)
	fr.owned = append(fr.owned, fresh...)
	defer fr.releaseOwned()
	direct, spray := fr.schedule(fresh)
	// The sandwich helper is new every round, bound before the fire time and
	// closed when the round ends: a socket that probed both observers in an
	// earlier round would reuse those mappings and bracket nothing.
	var helper *udpSock
	if fr.side.Sandwich && rt.sandwichOK() && len(fr.w.fs.observers) > int(nat.SandwichAfter) && len(direct)+len(spray) > 0 {
		if helper = rt.socks.sandwichHelper(ctx, fr.w.primary); helper != nil {
			defer rt.socks.release(helper)
		}
	}
	if rt.sleepUntil(ctx, fr.run.fireAt) != nil {
		return
	}
	before, after := helper != nil, helper != nil // the probes around the round's first punch
	reobserveAt := fr.reobserveAt()               // zero once done, or when the round does not re-observe
	var held, again []sendItem                    // held back by the run guard; to try again now
	for ctx.Err() == nil {
		select {
		case more := <-fr.inject:
			direct = append(fr.extraItems(more, rt.clk.Now()), direct...)
		default:
		}
		if fr.halted.Load() {
			// A halted round initiates nothing more; it still answers
			// through the read loops until it ends.
			direct, spray, held, again = nil, nil, nil, nil
			fr.waitUntil(ctx, farFuture)
			continue
		}
		now := rt.clk.Now()
		if !reobserveAt.IsZero() && !now.Before(reobserveAt) {
			fr.reobserve(ctx)
			reobserveAt = time.Time{}
			continue
		}
		converged := rt.punch.hasConverged()
		var it sendItem
		switch {
		case len(again) > 0:
			it, again = again[0], again[1:]
		case len(direct) > 0 && !direct[0].due.After(now):
			it, direct = direct[0], direct[1:]
		case !converged && len(spray) > 0 && !spray[0].due.After(now):
			it, spray = spray[0], spray[1:]
		default:
			wake := farFuture
			if len(direct) > 0 {
				wake = direct[0].due
			}
			if !converged && len(spray) > 0 && spray[0].due.Before(wake) {
				wake = spray[0].due
			}
			if !reobserveAt.IsZero() && reobserveAt.Before(wake) {
				wake = reobserveAt
			}
			fr.waitUntil(ctx, wake)
			continue
		}
		if it.slot > 0 {
			// A paced socket opens when its first packet is due; none opens
			// once the peer heard us, or after a halt.
			if it.sock = fr.pacedSocket(ctx, it.slot); it.sock == nil {
				continue
			}
		}
		if converged && !rt.punch.isHit(it.to) && !fr.keepAfterContact(it) {
			continue
		}
		if it.hops > 0 && rt.punch.isHit(it.to) {
			it.hops = 0 // an answered target gets normal TTL (receiver_full)
		}
		if before {
			fr.sandwichProbe(ctx, helper, nat.SandwichBefore)
			before = false
		}
		h := udpwire.Header{Type: udpwire.TPunch, Round: fr.run.plan.Round, Cand: it.cand}
		err := rt.sender.Send(ctx, it.sock, it.to, &h, nil,
			sendOpt{class: classInitiate, stage: it.stage, hops: it.hops, round: fr.meter, quota: it.quota})
		if errors.Is(err, errRun) {
			held = append(held, it)
			continue
		}
		if after {
			fr.sandwichProbe(ctx, helper, nat.SandwichAfter)
			after = false
		}
		if it.hops > 0 && it.sock.noLowTTL.Load() {
			rt.lowTTLDegraded(fr.w)
		}
		switch {
		case err == nil:
			again, held = append(again, held...), held[:0]
		case errors.Is(err, errBudget) && it.quota == quotaTargets:
		case errors.Is(err, errBudget):
			if !fr.budgetSaid.Swap(true) {
				rt.progress(progressEvent{stage: stageBudgetExhausted, status: protocol.StatusInfo, family: fr.w.fam, round: fr.run.plan.Round})
			}
			planned := func(it sendItem) bool { return it.quota == quotaPlan }
			direct, held, again = slices.DeleteFunc(direct, planned), slices.DeleteFunc(held, planned), slices.DeleteFunc(again, planned)
			spray = nil
		case errors.Is(err, errStopped):
			return
		case errors.Is(err, errUnreachable):
			direct = dropTarget(direct, it.to)
			spray = dropTarget(spray, it.to)
			held, again = dropTarget(held, it.to), dropTarget(again, it.to)
		case errors.Is(err, errRejected):
			// The gate's target limits refused it: nothing was written,
			// so it is no write failure.
		default:
			if rt.sender.writeBlocked(rt.clk.Now()) {
				r := protocol.ReasonUDPBlocked
				fr.run.fatal.CompareAndSwap(nil, &r)
				rt.udpBlocked.Store(true)
				rt.punch.notify()
				return
			}
			fr.writeSpike(rt.clk.Now())
		}
	}
}

// keepAfterContact reports whether a session that may keep extra paths
// still sends a planned packet once the peer was heard: a Direct packet of
// the family's primary socket, so that the other families and kinds of
// network get their chance to carry the peer's packets before the
// nomination picks the extra paths. Spraying stops
// as always, and Confirm stops everything.
func (fr *familyRound) keepAfterContact(it sendItem) bool {
	return fr.rt.opts.MaxPaths > 1 && it.stage == txDirect && it.slot == 0 && it.sock == fr.w.primary
}

// Failure spikes that halt a background round: this many paced
// sockets failing to bind in a row, or this many send failures within
// spikeWindow.
const (
	haltBindRun  = 8
	haltWrites   = 8
	spikeWindow  = time.Second
	pacedPurpose = PurposeBirthday
)

// background reports whether the round is the slow birthday of a
// Background session, the one a failure spike halts.
func (fr *familyRound) background() bool { return fr.run.plan.Budget == protocol.BudgetBackground }

// socketsBeforeFiring is how many of a side's sockets the round binds
// before firing: all of them, or only the primary when they are paced.
func socketsBeforeFiring(side protocol.FamilySide) int {
	if side.OpenPerSec > 0 {
		return 1
	}
	return int(max(side.Sockets, 1))
}

// pacedSocket returns the paced socket of slot, binding it on first use on
// the primary's IP; nil once the peer heard us, after a halt, or when the
// bind failed — counted in bind_failed, and a run of haltBindRun failures
// in a background round halts it. A socket the session's socket budget or
// index space refuses is no such failure: it says nothing about the host,
// and the sockets already open keep sending. Hearing the peer is not
// enough: after a one-way round the birthday aims these sockets at the
// source heard, and only a reply from one of them can reach the peer.
func (fr *familyRound) pacedSocket(ctx context.Context, slot int) *udpSock {
	if slot >= len(fr.paced) {
		return nil
	}
	if s := fr.paced[slot]; s != nil || fr.tried[slot] {
		return s
	}
	if fr.rt.punch.heardBack() || fr.halted.Load() {
		return nil
	}
	fr.tried[slot] = true
	rt := fr.rt
	s, err := rt.socks.pacedSocket(ctx, fr.w.primary, pacedPurpose)
	if err != nil {
		fr.lateFailed.Add(1)
		if errors.Is(err, errNoSockets) {
			return nil
		}
		if fr.bindRun++; fr.bindRun >= haltBindRun && fr.background() {
			fr.halted.Store(true)
		}
		return nil
	}
	fr.bindRun = 0
	fr.paced[slot] = s
	fr.owned = append(fr.owned, s)
	for si, st := range fr.side.Stages {
		if st.Kind != protocol.StageDirect {
			continue
		}
		for ti, t := range st.Targets {
			if cand, ok := udpwire.CandID(si, ti); ok {
				rt.punch.planTarget(s.id, cand, netaddr.Canon(t), candidate.KindObserved)
			}
		}
	}
	return s
}

// writeSpike notes a send failure of a background round and halts it at
// haltWrites failures within spikeWindow.
func (fr *familyRound) writeSpike(now time.Time) {
	if !fr.background() {
		return
	}
	fr.writeFails = append(slices.DeleteFunc(fr.writeFails, func(t time.Time) bool { return now.Sub(t) > spikeWindow }), now)
	if len(fr.writeFails) >= haltWrites {
		fr.halted.Store(true)
	}
}

func dropTarget(items []sendItem, to netip.AddrPort) []sendItem {
	return slices.DeleteFunc(items, func(it sendItem) bool { return it.to == to })
}

// waitUntil sleeps until t, an injected target or the end of the round.
func (fr *familyRound) waitUntil(ctx context.Context, t time.Time) {
	rt := fr.rt
	tm := rt.clk.NewTimer(max(t.Sub(rt.clk.Now()), 0))
	defer tm.Stop()
	select {
	case <-ctx.Done():
	case <-tm.C():
	case more := <-fr.inject:
		// put it back for the loop, which prepends it with fresh due times
		select {
		case fr.inject <- more:
		default:
		}
	}
}

// bindFresh binds the round's fresh sockets on the primary's IP at
// the ports both sides draw from the pair seed, by the index of the draw;
// a port this host cannot bind — taken, privileged, past the socket budget
// — is skipped (nil) and counted in round_result.bind_failed. A side
// without a fresh stage, a reply-only one, an unverified family and the
// NoPrediction ablation bind none.
func (fr *familyRound) bindFresh(ctx context.Context) []*udpSock {
	rt, w := fr.rt, fr.w
	i := slices.IndexFunc(fr.side.Stages, func(st protocol.Stage) bool { return st.Kind == protocol.StageFresh })
	if i < 0 || fr.side.Role == protocol.SideReplyOnly || rt.abl.NoPrediction || w.unverified {
		return nil
	}
	ports := plan.FreshPorts(fr.pairSeed(), int(fr.side.Stages[i].Count))
	out := make([]*udpSock, len(ports))
	for k, port := range ports {
		if ctx.Err() != nil {
			break
		}
		s, err := rt.socks.freshSocket(ctx, w.primary, port)
		if err != nil {
			fr.lateFailed.Add(1)
			continue
		}
		out[k] = s
	}
	return out
}

// releaseOwned closes the round's own sockets — fresh and paced — that
// never heard the peer; one that did holds candidate pairs and stays to
// the session's end.
func (fr *familyRound) releaseOwned() {
	for _, s := range fr.owned {
		if s != nil && !fr.rt.punch.heardOn(s.local) {
			fr.rt.socks.release(s)
		}
	}
}

// sandwichProbe sends the sandwich probe of phase `phase` from the round's
// helper socket: the one before the round's first punch to observer 0, the
// one after it to observer 1, so that the two new
// mappings bracket the punch's.
func (fr *familyRound) sandwichProbe(ctx context.Context, helper *udpSock, phase uint8) {
	fr.rt.probeObserver(ctx, helper, fr.w.fs.observers[phase], 0, &sandwichTag{round: fr.run.plan.Round, phase: phase})
}

// lowTTLDegraded reports, once per family, that a socket refused the low TTL:
// the family sends with normal TTL from now on.
func (rt *runtime) lowTTLDegraded(w *worker) {
	if w.lowTTLOff.Swap(true) {
		return
	}
	rt.addWarn(protocol.WarnLowTTLUnsupported)
	rt.progress(progressEvent{stage: stageLowTTLUnsupported, status: protocol.StatusInfo, family: w.fam})
}
