package holepunch

import (
	"context"
	"net/netip"
	"sync/atomic"
	"time"

	"github.com/djylb/holepunch/internal/candidate"
	"github.com/djylb/holepunch/internal/faultinject"
	"github.com/djylb/holepunch/internal/udpwire"
	"github.com/djylb/holepunch/protocol"
)

// nominationEvents bounds the packet facts waiting for the nomination
// goroutine; a full queue drops the newest (retransmissions repeat it).
const nominationEvents = 256

// Fault-injection points of the handshake.
const (
	fiNominationRetry = "nomination.retry"
	fiHandoverAck     = "handover.ack"
)

type candEventKind uint8

const (
	evPacket     candEventKind = iota + 1 // punch or success: the pair carries traffic
	evNominate                            // responder
	evAccept                              // initiator
	evReady                               // responder
	evAck                                 // initiator
	evUpper                               // a non-holepunch datagram from the nominated remote
	evReadFailed                          // a socket's read loop ended on an error
)

// candEvent is a packet fact for the nomination goroutine.
type candEvent struct {
	kind          candEventKind
	local, remote netip.AddrPort
	fam           protocol.Family
	epoch         uint16
	rtt           time.Duration
	ckind         candidate.Kind
	at            time.Time
	peerSock      uint8 // the header sock of the peer's packet
	slot, paths   uint8 // PATH_SLOT and PATHS of a handshake packet
}

// nominator owns the session's candidate.Manager on one goroutine
// ("nominate"): the read loops post packet facts, the goroutine feeds them to
// the pure state machine, runs its timers and performs the actions it returns
// (nominate, accept, ready, handover_ack through the Handshake class; Confirm;
// HandOver; Fail). Owning the machine on one goroutine needs no lock around
// it. It runs in the punching group and is joined by finish.
//
// The nominator is created with the runtime, because the read loops post to
// it from the probing phase on, but the machine is not: run builds it from
// the configuration it is started with, once the summary has settled the
// handover timeout. The read loops thus only ever touch events and pair.
type nominator struct {
	rt     *runtime
	events chan candEvent
	pair   atomic.Pointer[pairKey]   // the pair being nominated or adopted, for upper-layer evidence
	extra  atomic.Pointer[[]pairKey] // the committed extra paths' pairs, upper-layer evidence too

	// owned by the goroutine; states is read only after it was joined
	mgr         *candidate.Manager // built by run
	lastNomEp   uint16
	lastAdoptEp uint16
	states      map[pairKey]pairState // the pairs that carried traffic, for Diagnostics
}

// pairState is a pair's furthest candidate state as this side saw it.
type pairState struct {
	fam   protocol.Family
	state candidate.State
}

// candidateStateNames are the keys of FamilyDiagnostics.Candidates.
var candidateStateNames = map[candidate.State]string{
	candidate.StateDiscovered: "discovered",
	candidate.StateSucceeded:  "succeeded",
	candidate.StateNominated:  "nominated",
	candidate.StateConfirmed:  "confirmed",
	candidate.StateClosed:     "closed",
}

func newNominator(rt *runtime) *nominator {
	return &nominator{rt: rt, events: make(chan candEvent, nominationEvents), states: map[pairKey]pairState{}}
}

// raise records that a pair reached state s.
func (n *nominator) raise(k pairKey, f protocol.Family, s candidate.State) {
	if cur, ok := n.states[k]; !ok || s > cur.state {
		n.states[k] = pairState{f, s}
	}
}

// post hands a fact to the goroutine without blocking; a full queue drops
// it (a retransmission will come again).
func (n *nominator) post(ev candEvent) {
	select {
	case n.events <- ev:
	default:
	}
}

// run is the nomination goroutine. It builds the state machine from cfg and
// sleeps on one timer armed at the machine's next deadline, so it does not
// wake while no handshake is in progress.
func (n *nominator) run(ctx context.Context, cfg candidate.Config) {
	n.mgr = candidate.NewManager(cfg)
	t := n.rt.clk.NewTimer(time.Hour)
	t.Stop()
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case ev := <-n.events:
			n.handle(ctx, ev)
		drain:
			for {
				select {
				case ev := <-n.events:
					n.handle(ctx, ev)
				default:
					break drain
				}
			}
		case <-t.C():
			n.perform(ctx, n.mgr.Tick(n.rt.clk.Now()))
		}
		if at, ok := n.mgr.NextDeadline(); ok {
			t.Reset(max(at.Sub(n.rt.clk.Now()), 0))
		} else {
			t.Stop()
		}
	}
}

func (n *nominator) handle(ctx context.Context, ev candEvent) {
	m := n.mgr
	if ev.kind != evUpper && ev.kind != evReadFailed {
		m.Touch(ev.at, ev.remote)
	}
	var acts []candidate.Action
	switch ev.kind {
	case evPacket:
		if ev.ckind != candidate.KindUnknown {
			m.Observe(ev.at, ev.local, ev.remote, ev.fam, ev.ckind)
		}
		m.Success(ev.at, ev.local, ev.remote, ev.fam, ev.rtt)
		m.Describe(ev.local, ev.remote, n.rt.pathKind(ev.fam, ev.remote, ev.ckind), ev.peerSock)
		n.raise(pairKey{ev.local, ev.remote}, ev.fam, candidate.StateSucceeded)
	case evNominate:
		if ev.slot != 0 {
			acts = m.RecvExtraNominate(ev.at, ev.epoch, ev.slot, ev.local, ev.remote)
		} else {
			acts = m.RecvNominate(ev.at, ev.epoch, ev.local, ev.remote, ev.fam)
		}
	case evAccept:
		if ev.slot != 0 {
			acts = m.RecvExtraAccept(ev.at, ev.epoch, ev.slot, ev.local, ev.remote)
		} else {
			acts = m.RecvAccept(ev.at, ev.epoch, ev.remote, ev.paths)
		}
	case evReady:
		acts = m.RecvReady(ev.at, ev.epoch, ev.remote, ev.paths)
	case evAck:
		acts = m.RecvHandoverAck(ev.at, ev.epoch, ev.remote)
	case evUpper:
		acts = m.RecvUpperLayer(ev.at, ev.local, ev.remote)
	case evReadFailed:
		acts = m.ReadFailed(ev.at, ev.local)
	}
	n.perform(ctx, acts)
}

// perform carries out the state machine's actions in order.
func (n *nominator) perform(ctx context.Context, acts []candidate.Action) {
	rt := n.rt
	for _, a := range acts {
		switch a.Kind {
		case candidate.SendNominate, candidate.SendAccept, candidate.SendReady, candidate.SendAck:
			k := pairKey{a.Local, a.Remote}
			if a.Slot == 0 {
				n.pair.Store(&k)
			}
			n.raise(k, a.Family, candidate.StateNominated)
			if a.Kind == candidate.SendReady {
				n.noteExtras()
			}
			n.sendHandshake(ctx, a)
		case candidate.Confirm:
			n.raise(pairKey{a.Local, a.Remote}, a.Family, candidate.StateConfirmed)
			n.noteExtras()
			rt.onConfirm(a, rt.clk.Now())
		case candidate.HandOver:
			rt.onHandOver(a, n.mgr.Extras())
		case candidate.Fail:
			rt.onHandoverFailed()
		}
	}
}

// noteExtras publishes the committed extra paths — the initiator's at its
// first ready, the responder's at Confirm — for the read loops: their
// upper-layer datagrams are handover evidence too.
func (n *nominator) noteExtras() {
	var ks []pairKey
	for _, c := range n.mgr.Extras() {
		k := pairKey{c.Local, c.Remote}
		ks = append(ks, k)
		n.raise(k, c.Family, candidate.StateConfirmed)
	}
	if len(ks) > 0 {
		n.extra.Store(&ks)
	}
}

// watched reports whether a non-holepunch datagram on (local, remote) is
// upper-layer evidence for the state machine: the nominated or adopted
// pair, or a committed extra path.
func (n *nominator) watched(local, remote netip.AddrPort) bool {
	if p := n.pair.Load(); p != nil && p.local == local && p.remote == remote {
		return true
	}
	if ks := n.extra.Load(); ks != nil {
		for _, k := range *ks {
			if k.local == local && k.remote == remote {
				return true
			}
		}
	}
	return false
}

// sendHandshake sends nominate, accept, ready or handover_ack on the pair's
// socket (Handshake class: the 256-packet reserve, never MaxPackets). An
// extra path's nominate and accept carry its slot, the primary path's
// accept the room for extra paths and ready the committed slots.
func (n *nominator) sendHandshake(ctx context.Context, a candidate.Action) {
	rt := n.rt
	s := rt.socks.byAddr(a.Local)
	if s == nil {
		return
	}
	h := udpwire.Header{Aux: a.Epoch, Cand: udpwire.NoCand, Round: rt.currentRound()}
	var t *udpwire.TLVs
	stage := txHandshake
	switch a.Kind {
	case candidate.SendNominate:
		h.Type = udpwire.TNominate
		if faultinject.Point(fiNominationRetry) != nil {
			return
		}
		if a.Slot != 0 {
			t = &udpwire.TLVs{Slot: a.Slot}
		} else if a.Epoch != n.lastNomEp {
			n.lastNomEp = a.Epoch
			rt.progress(progressEvent{stage: stageNominated, status: protocol.StatusInfo, family: a.Family, remote: a.Remote})
		}
	case candidate.SendAccept:
		h.Type = udpwire.TAccept
		t = &udpwire.TLVs{RxCount: uint32(rt.punch.rx.Load()), HasRx: true, Slot: a.Slot, Paths: a.Paths}
		if a.Slot == 0 && a.Epoch != n.lastAdoptEp {
			n.lastAdoptEp = a.Epoch
			rt.phases.advanceFamily(a.Family, protocol.PhaseNegotiating, stageAdopted, rt.clk.Now())
			rt.progress(progressEvent{stage: stageAdopted, status: protocol.StatusInfo, family: a.Family, remote: a.Remote})
		}
	case candidate.SendReady:
		h.Type, stage = udpwire.TReady, txHandover
		if a.Paths != 0 {
			t = &udpwire.TLVs{Paths: a.Paths}
		}
	case candidate.SendAck:
		h.Type, stage = udpwire.THandoverAck, txHandover
		if faultinject.Point(fiHandoverAck) != nil {
			return
		}
		t = &udpwire.TLVs{RxCount: uint32(rt.punch.rx.Load()), HasRx: true}
	case candidate.Confirm, candidate.HandOver, candidate.Fail:
		return // not a handshake packet
	}
	_ = rt.sender.Send(ctx, s, a.Remote, &h, t, sendOpt{class: classHandshake, stage: stage})
}

// candidates counts the pairs of family f by state for Diagnostics, the
// planned targets that never answered counting as discovered. It is called
// after the nomination goroutine was joined.
func (n *nominator) candidates(f protocol.Family, planned int) map[string]int {
	out := map[string]int{}
	answered := 0
	for _, ps := range n.states {
		if ps.fam == f {
			out[candidateStateNames[ps.state]]++
			answered++
		}
	}
	if d := planned - answered; d > 0 {
		out[candidateStateNames[candidate.StateDiscovered]] += d
	}
	return out
}
