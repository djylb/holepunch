package probe

import (
	"slices"
	"time"

	"github.com/djylb/holepunch/internal/faultinject"
	"github.com/djylb/holepunch/internal/nat"
	"github.com/djylb/holepunch/internal/udpwire"
	"github.com/djylb/holepunch/protocol"
)

// pointRecv is the fault injection point of every delivered packet.
const pointRecv = "probe.recv"

// handle processes one delivered packet.
func (s *runState) handle(in inbound) {
	if err := faultinject.Point(pointRecv); err != nil {
		s.counters.Rejected++
		return
	}
	at := in.at
	if at.IsZero() {
		at = s.p.clk.Now()
	}
	el := at.Sub(s.t0)
	if in.stun {
		s.onSTUN(in, el)
		return
	}
	switch in.h.Type {
	case udpwire.TProbeAck:
		s.onAck(in, at, el)
	case udpwire.TProbeExtra:
		s.onExtra(in, el)
	case udpwire.TProbeAlt:
		s.onAlt(in)
	default:
		s.counters.Rejected++ // a hairpin packet outside the self-test
	}
}

// match returns the probe a reply answers, checking that it echoes the probe
// (seq, ts, sock, observer id), comes from the server role and arrived on the
// socket the probe left from.
func (s *runState) match(in inbound) *probeRec {
	for _, r := range s.recs {
		if r.seq != in.h.EchoSeq {
			continue
		}
		if r.ts != in.h.EchoTS || in.h.Role != udpwire.RoleServer || in.sock != r.tg.sockID ||
			in.h.Sock != r.tg.sockID || in.h.Aux != uint16(r.tg.obs.ID) {
			return nil
		}
		return r
	}
	return nil
}

// onAck accepts an ack from the probed observer's address: a sample of the
// observed mapping with its RTT and cookie, and the server's declarations.
func (s *runState) onAck(in inbound, at time.Time, el time.Duration) {
	r := s.match(in)
	if r == nil || in.from != r.tg.obs.Addr || !in.t.Observed.IsValid() {
		s.counters.Rejected++
		return
	}
	if r.acked {
		return // a duplicate of an answer already taken
	}
	r.acked = true
	tg := r.tg
	if !tg.acked {
		tg.acked = true
		tg.observed = unmap(in.t.Observed)
	}
	rtt := max(el-r.at, 0)
	s.table.Record(tg.key, in.t.Observed, el, rtt, in.t.Cookie)
	s.noteRTT(rtt, in.h.TS, at)
	// QUOTA_EXHAUSTED answers the request this probe made: on a WANT_ALT ack
	// it is the alt quota, which says nothing about the extras the top-up
	// asks for (natprobe sets FC for the WANT_* flag it served).
	if in.h.FC && r.want == wantExtra {
		s.extraQuotaOut = true
	}
	if in.h.FA && r.want == wantExtra && !r.extraDeclared {
		r.extraDeclared, r.extraPort, r.extraDue = true, in.t.ExtraPort, el+s.extraWait()
		if i := slices.IndexFunc(s.stash, func(x stashed) bool { return x.seq == r.seq }); i >= 0 {
			x := s.stash[i]
			s.stash = slices.Delete(s.stash, i, i+1)
			if x.from.Port() == r.extraPort {
				s.extraArrived(r)
			}
		}
	}
	if in.h.FB && r.want == wantAlt && !r.altDeclared {
		r.altDeclared, r.altDue = true, el+s.extraWait()
	}
}

// onExtra accepts an extra from the probed observer's IP and the port its ack
// declared; one that arrives before its ack waits up to 250 ms in the stash.
func (s *runState) onExtra(in inbound, el time.Duration) {
	r := s.match(in)
	if r == nil || r.want != wantExtra || in.from.Addr() != r.tg.obs.Addr.Addr() || in.from.Port() == r.tg.obs.Addr.Port() {
		s.counters.Rejected++
		return
	}
	switch {
	case r.extraSeen:
	case !r.acked:
		if len(s.stash) < maxStash {
			s.stash = append(s.stash, stashed{seq: r.seq, from: in.from, at: el})
		}
	case r.extraDeclared && in.from.Port() == r.extraPort:
		s.extraArrived(r)
	default:
		s.counters.Rejected++
	}
}

// onAlt accepts a change-IP reply from an alt observer's IP. It is EIF
// evidence only while the alt IP has never been contacted:
// once the solicited probes went out, an ADF NAT lets the late copy in too,
// so a reply arriving then proves nothing and is dropped.
func (s *runState) onAlt(in inbound) {
	r := s.match(in)
	if r == nil || r.want != wantAlt || !slices.ContainsFunc(s.alts, func(o nat.Observer) bool { return o.Addr.Addr() == in.from.Addr() }) {
		s.counters.Rejected++
		return
	}
	if r.altSeen || s.altPhase != altUnsolicited {
		return
	}
	r.altSeen = true
	f := nat.FilterEvidence{Socket: r.tg.sockID, Observer: r.tg.obs.ID, AltSeen: 1}
	if !r.altSettled {
		r.altSettled = true
		f.AltDeclared = 1
	}
	s.table.AddFilter(f)
}

// extraArrived records positive filtering evidence; a declaration not yet
// settled counts as declared now.
func (s *runState) extraArrived(r *probeRec) {
	if r.extraSeen {
		return
	}
	r.extraSeen = true
	f := nat.FilterEvidence{Socket: r.tg.sockID, Observer: r.tg.obs.ID, ExtraSeen: 1}
	if !r.extraSettled {
		r.extraSettled = true
		f.ExtraDeclared = 1
	}
	s.table.AddFilter(f)
}

// onSTUN accepts a Binding Success from the server the request went to. An
// answer that names no address of the family (a NAT64 path answers an IPv6
// request with IPv4) ends the server's wait like any answer but enters
// nothing.
func (s *runState) onSTUN(in inbound, el time.Duration) {
	i := slices.IndexFunc(s.stun, func(st *stunTarget) bool { return st.txid == in.txid })
	if i < 0 || s.stun[i].done || in.from != s.stun[i].addr {
		s.counters.Rejected++
		return
	}
	st := s.stun[i]
	st.done = true
	if ip := in.mapped.Addr(); !s.p.spec.Family.Matches(ip) || ip.IsMulticast() {
		return
	}
	st.mapped = true
	s.table.Record(nat.PointKey{Socket: s.p.primaryID, Source: nat.SourceSTUN, Observer: st.idx}, in.mapped, el, max(el-st.last, 0), 0)
}

// noteRTT keeps the minimum RTT sample and the clock offset estimated on it:
// local wall clock at the sample's midpoint minus the server ts (Unix ms mod
// 2³²). The offset is diagnostic only. An answer read at the instant
// of its probe is below the clock's resolution (Windows' monotonic clock
// ticks at 0.5 ms or coarser): the smallest RTT there is, not a missing one.
func (s *runState) noteRTT(rtt time.Duration, serverTS uint32, at time.Time) {
	rtt = max(rtt, time.Nanosecond)
	if s.minRTT > 0 && rtt >= s.minRTT {
		return
	}
	s.minRTT = rtt
	mid := at.Add(-rtt / 2).UnixMilli()
	s.clock = protocol.ClockSample{
		RTTMs:    uint32((rtt + time.Millisecond - 1) / time.Millisecond),
		OffsetMs: int64(int32(uint32(mid) - serverTS)),
	}
}
