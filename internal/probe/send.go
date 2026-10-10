package probe

import (
	"net/netip"
	"time"

	"github.com/djylb/holepunch/internal/faultinject"
	"github.com/djylb/holepunch/internal/life"
	"github.com/djylb/holepunch/udpwire"
)

// pointSend is the fault injection point of every probe-class write.
const pointSend = "probe.send"

// send seals and writes one probe for tg; a retransmission takes a new seq,
// so each answer pairs with exactly one send and its RTT is unambiguous.
// Nothing is sent once the family's server budget is spent.
func (s *runState) send(tg *target, now time.Duration) {
	if s.budget <= 0 {
		return
	}
	s.budget--
	h := udpwire.Header{Type: udpwire.TProbe, Role: s.p.role, Retx: tg.sends > 0, FA: tg.want == wantExtra, FB: tg.want == wantAlt,
		Sock: tg.sockID, Cand: udpwire.NoCand, Aux: uint16(tg.obs.ID), Seq: s.codec.NextSeq(), TS: s.codec.Now()}
	pkt, err := s.codec.Seal(s.buf[:0], &h, nil, 0)
	if err == nil {
		err = writeProbe(tg.sock, pkt, tg.obs.Addr)
	}
	tg.sends++
	tg.last = now
	if err != nil {
		s.counters.SendErrors++
		s.batchFail++
		return
	}
	s.batchOK++
	s.batchForeign = s.batchForeign || tg.kind == kindLAN
	s.recs = append(s.recs, &probeRec{seq: h.Seq, ts: h.TS, tg: tg, at: now, want: tg.want})
	s.table.NoteSent(tg.key, h.Seq, now)
	switch tg.kind {
	case kindMain, kindLAN:
		s.counters.Primary++
	case kindTopUp:
		s.counters.TopUp++
	case kindSecond:
		s.counters.Second++
	case kindSibling:
		s.counters.Sibling++
	case kindAlt:
		s.counters.Alt++
	}
}

// sendSTUN writes one Binding Request to a STUN server from the primary socket,
// within the family's STUN budget. STUN is an optional hint: a failed write is
// counted apart and never counts towards udp_blocked, and a request that left
// only marks the step as one whose ICMP may be the STUN server's (foreign).
func (s *runState) sendSTUN(st *stunTarget, now time.Duration) {
	if s.stunBudget <= 0 {
		return
	}
	s.stunBudget--
	st.sends++
	st.last = now
	s.counters.STUN++
	if err := writeProbe(s.p.primary, appendSTUNRequest(s.buf[:0], st.txid), st.addr); err != nil {
		s.counters.STUNErrors++
		return
	}
	s.batchForeign = true
}

// writeProbe calls the runtime's WriteTo inside a recover boundary, so that a
// panicking implementation is one failed send, after the probe.send fault
// injection point.
func writeProbe(h SocketHandle, b []byte, to netip.AddrPort) (err error) {
	if err = faultinject.Point(pointSend); err != nil {
		return err
	}
	if perr := life.Safe("probe/write", func() { err = h.WriteTo(b, to) }); perr != nil {
		return perr
	}
	return err
}
