package holepunch

import (
	"context"
	"net/netip"
	"slices"
	"time"

	"github.com/djylb/holepunch/internal/netaddr"
	"github.com/djylb/holepunch/protocol"
	"github.com/djylb/holepunch/udpwire"
)

// Re-observation of the primary socket's mapping while punching. A NAT may
// change the external address of a mapping after the summary: a WAN reconnect
// or a carrier pool moves it to another IP, an expired mapping comes back on
// another port. Each side then aims at the peer's dead address, and a filtering
// peer drops what the moved side sends from its new one, so neither hears the
// other. The moved side cannot tell the peer itself — a self-reported address
// is never a target — but natprobe can see the new mapping, and coord can push
// it to the peer as peer_targets{source: drift} once it is verified.
//
// So a round that has heard nothing from the peer halfway through its
// window sends one probe from the primary socket to the family's first
// global observer (normally observer 0). When its ack shows a mapping this
// side did not know, round_result carries it as remap with the ack's
// cookie: the echo verifies the new mapping as the probe report's echo
// verified the old ones, and coord pushes it with the next go.

// reobservation is a round's re-observation probe awaiting its ack.
type reobservation struct {
	seq      uint32 // the probe's seq; 0 when none is in flight
	observer uint8
	to       netip.AddrPort
}

// reobserveAt is when the family round re-observes the primary socket's
// mapping, or the zero time when it does not. It is halfway through the
// window, so that the ack is back for round_result, and only in a round that
// another can follow (not final) of a family the server observes. Under the
// NoAssistRelay ablation the drift push it feeds would be dropped, so it is
// off too.
func (fr *familyRound) reobserveAt() time.Time {
	if _, ok := fr.w.reobserver(); !ok || fr.run.plan.Final || fr.rt.abl.NoAssistRelay {
		return time.Time{}
	}
	return fr.run.fireAt.Add(fr.run.end.Sub(fr.run.fireAt) / 2)
}

// reobserver is the observer a re-observation probe goes to: the family's
// first main-group observer on a global address. natprobe takes what an
// observer on a private address sees as LAN evidence only, and an
// unverified family has no observer at all.
func (w *worker) reobserver() (protocol.ObserverSpec, bool) {
	if w.unverified {
		return protocol.ObserverSpec{}, false
	}
	return globalObserver(w.fs.observers)
}

// reobserve sends the round's re-observation probe when the family has had
// no peer packet this round: one probe without WANT flags from the primary
// socket to the re-observation observer, through the gate's probe class
// (natprobe counts it against the session's probe budget). The seq is
// registered before the probe leaves, so the read loop recognises the ack
// however fast it comes.
func (fr *familyRound) reobserve(ctx context.Context) {
	rt, w := fr.rt, fr.w
	st := rt.punch
	obs, ok := w.reobserver()
	if !ok {
		return
	}
	to := netaddr.Canon(obs.Addr)
	h := udpwire.Header{Type: udpwire.TProbe, Cand: udpwire.NoCand, Aux: uint16(obs.ID)}
	st.mu.Lock()
	rs := st.statsFor(w.fam)
	quiet := rs.recv == 0
	if quiet {
		h.Seq = rt.codec.NextSeq()
		rs.reobserve = reobservation{seq: h.Seq, observer: obs.ID, to: to}
	}
	st.mu.Unlock()
	if !quiet {
		return
	}
	_ = rt.sender.Send(ctx, w.primary, to, &h, nil, sendOpt{class: classProbe, stage: txProbe})
}

// reobserved consumes the ack of the current round's re-observation probe —
// on the primary socket, echoing its seq, from the observer it went to —
// and reports whether it was one. A mapping this side did not know yet (the
// summary's verified mappings of the primary socket and the remaps reported
// before) becomes the round's remap and drift evidence. The traits are left
// alone: a new external address is an event of the network, not a behaviour
// of the NAT the traits memory should learn. An ack without a cookie (the
// observer had no slot left) cannot be verified and is not reported.
func (rt *runtime) reobserved(s *udpSock, from netip.AddrPort, h *udpwire.Header, t *udpwire.TLVs) bool {
	st := rt.punch
	if h.Type != udpwire.TProbeAck || !st.active.Load() {
		return false
	}
	w := rt.fam(s.fam).worker
	if w == nil || s != w.primary {
		return false
	}
	st.mu.Lock()
	rs := st.stats[s.fam]
	if rs == nil || rs.reobserve.seq == 0 || h.EchoSeq != rs.reobserve.seq || h.Aux != uint16(rs.reobserve.observer) ||
		netaddr.Canon(from) != rs.reobserve.to {
		st.mu.Unlock()
		return false
	}
	observer := rs.reobserve.observer
	rs.reobserve = reobservation{}
	mapped := netaddr.Canon(t.Observed)
	fresh := t.Cookie != 0 && reportable(s.fam, mapped) &&
		!slices.Contains(w.selfMapped, mapped) && !slices.Contains(st.remapped[s.fam], mapped)
	if fresh {
		// At most one a round: the list stays within the wire's 8 rounds.
		st.remapped[s.fam] = append(st.remapped[s.fam], mapped)
		rs.remap = &protocol.Remap{Observer: observer, Observed: mapped, Cookie: t.Cookie}
		rs.drift = true
	}
	round := st.round
	st.mu.Unlock()
	if fresh {
		rt.progress(progressEvent{stage: stageDriftDetected, status: protocol.StatusInfo, family: s.fam, round: round})
	}
	return true
}

// reportable reports whether a can be a remap of family fam on the wire:
// round_result validation refuses anything else, and with it the whole frame.
func reportable(fam protocol.Family, a netip.AddrPort) bool {
	ip := a.Addr()
	return a.Port() != 0 && fam.Matches(ip) && !ip.IsUnspecified() && !ip.IsMulticast()
}

// cloneRemap copies a remap for round_result.
func cloneRemap(r *protocol.Remap) *protocol.Remap {
	if r == nil {
		return nil
	}
	c := *r
	return &c
}
