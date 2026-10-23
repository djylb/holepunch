package natprobe

import (
	"context"
	crand "crypto/rand"
	"errors"
	"math"
	"math/rand/v2"
	"net"
	"net/netip"
	"sync/atomic"
	"time"

	"github.com/djylb/holepunch/internal/faultinject"
	"github.com/djylb/holepunch/internal/life"
	"github.com/djylb/holepunch/internal/nat"
	"github.com/djylb/holepunch/internal/netaddr"
	"github.com/djylb/holepunch/internal/udpwire"
	"github.com/djylb/holepunch/protocol"
	"github.com/djylb/holepunch/udpsock"
)

// Fault injection points of the packet path.
const (
	pointPacket = "natprobe.packet"
	pointExtra  = "natprobe.extra"
)

// Read-error handling: a conn that only fails must not spin a core. ICMP
// reports and truncated datagrams are not failures: a report names an
// earlier reply's client, a truncated datagram was received, and the socket
// reads on.
const (
	readErrorBurst = 64
	readErrorPause = 10 * time.Millisecond
)

// reader is one reader goroutine of a listener with its own buffers and
// random source (cookies, reply lengths), shared with no other goroutine.
// The packet path takes three short locks, never two at once: the source
// limiter's shard, the (session, role) state, and for a sandwich probe the
// session's event queue.
type reader struct {
	s     *Server
	l     *listener
	st    *readerStats
	rng   *rand.Rand
	h     udpwire.Header
	t     udpwire.TLVs
	buf   [2048]byte
	oob   [udpsock.ControlSize]byte // the destination report of a datagram read
	soob  [udpsock.ControlSize]byte // the source of a reply
	plain [udpwire.MaxPlaintext + udpwire.TagSize]byte
	wbuf  [udpwire.PeerOuterSize + udpwire.MaxPlaintext + udpwire.TagSize]byte
	obuf  [udpwire.MaxWrapped]byte // a reply in the opener form
}

func newReader(s *Server, l *listener, st *readerStats) *reader {
	var seed [32]byte
	_, _ = crand.Read(seed[:]) // crypto/rand.Read never fails (Go 1.24+)
	return &reader{s: s, l: l, st: st, rng: rand.New(rand.NewChaCha8(seed))}
}

// readLoop is the body of a reader goroutine. A panic in the loop itself,
// outside the per-packet boundary, stops this listener only.
func (s *Server) readLoop(ctx context.Context, l *listener, st *readerStats) {
	rd := newReader(s, l, st)
	if err := life.Safe("natprobe/read", func() { rd.loop(ctx) }); err != nil {
		st.panics.Add(1)
		s.logPanic(err)
		s.markDead(l)
	}
}

func (rd *reader) loop(ctx context.Context) {
	failures := 0
	for {
		n, src, dst, err := rd.read()
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) || rd.l.dead.Load() {
				return
			}
			if udpsock.IsICMPReport(err) {
				continue
			}
			if n > 0 {
				// A datagram longer than the buffer, which Windows reports as
				// an error with the truncated bytes: far longer than any
				// probe, so foreign, and no read failure — a flood of them
				// must not pause the reader.
				failures = 0
				rd.st.packetsIn.Add(1)
				rd.st.bytesIn.Add(uint64(n))
				rd.st.foreign.Add(1)
				continue
			}
			rd.st.readErrs.Add(1)
			if failures++; failures >= readErrorBurst {
				failures = 0
				if !pause(ctx, readErrorPause) {
					return
				}
			}
			continue
		}
		failures = 0
		if perr := life.Safe("natprobe/packet", func() { rd.process(rd.buf[:n], src, dst) }); perr != nil {
			rd.st.panics.Add(1)
			rd.s.logPanic(perr)
		}
	}
}

// read reads one datagram and, from a wildcard socket that reports it, the
// address it was sent to.
func (rd *reader) read() (n int, src netip.AddrPort, dst netip.Addr, err error) {
	if rd.l.msg == nil {
		n, src, err = rd.l.conn.ReadFromUDPAddrPort(rd.buf[:])
		return n, src, netip.Addr{}, err
	}
	n, oobn, _, src, err := rd.l.msg.ReadMsgUDPAddrPort(rd.buf[:], rd.oob[:])
	if err == nil {
		dst, _ = udpsock.DstAddr(rd.oob[:oobn])
	}
	return n, src, dst, err
}

// pause waits d or until ctx ends and reports whether d elapsed.
func pause(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}

// process handles one datagram: the
// opener form unwrapped, precheck, source rate, route unmasking and
// lookup (an unknown route is never decrypted), AEAD, role and observer,
// session rate, lifetime budget and replay, the slot, then replies to the
// source only, never more bytes than received. A probe that came as an
// opener opened a new flow of the client's, so the replies leave as
// openers too — the ack on the reverse of that flow, an extra or alt
// reply from a socket that has not sent to this client before — without
// any per-flow state on the server.
func (rd *reader) process(pkt []byte, src netip.AddrPort, dst netip.Addr) {
	st, l := rd.st, rd.l
	st.packetsIn.Add(1)
	st.bytesIn.Add(uint64(len(pkt)))
	if faultinject.Point(pointPacket) != nil {
		return
	}
	src = netaddr.Unmap(src)
	if src.Port() == 0 || !src.Addr().IsValid() || src.Addr().IsUnspecified() {
		st.foreign.Add(1) // no address a reply could go to
		return
	}
	size := len(pkt)
	wrapped := udpwire.Wrapped(pkt)
	if wrapped {
		inner, e := udpwire.Unwrap(pkt)
		switch e {
		case udpwire.OK:
			pkt = inner
		case udpwire.ErrShort:
			st.short.Add(1)
			return
		default:
			st.foreign.Add(1)
			return
		}
	}
	switch udpwire.Precheck(pkt, udpwire.MinProbePacket) {
	case udpwire.OK:
	case udpwire.ErrShort:
		st.short.Add(1)
		return
	default:
		st.foreign.Add(1)
		return
	}
	reg := rd.s.reg
	now := reg.now()
	mono := reg.mono(now)
	if !rd.s.src.allow(src.Addr(), mono) {
		st.rateSrc.Add(1)
		return
	}
	route, _ := udpwire.UnmaskRoute(pkt)
	e := reg.lookup(route)
	if e == nil || !e.alive(mono) {
		st.unknownRoute.Add(1)
		return
	}
	h, t := &rd.h, &rd.t
	switch e.codec.OpenProbe(pkt, rd.plain[:], h, t) {
	case udpwire.OK:
	case udpwire.ErrAuth:
		st.badAuth.Add(1)
		return
	case udpwire.ErrRoute:
		st.unknownRoute.Add(1)
		return
	default:
		st.badPayload.Add(1)
		return
	}
	if e.codec.CheckRole(h) != udpwire.OK {
		st.badPayload.Add(1)
		return
	}
	if !l.serves(h.Aux) {
		st.badObserver.Add(1)
		return
	}
	plan, verdict := rd.admit(e, h, src, now, mono, size, wrapped)
	if verdict != nil {
		verdict.Add(1)
		return
	}
	if wrapped {
		st.openers.Add(1)
	}
	rd.reply(e, h, src, dst, now, plan)
	// The coordinator gets sandwich events after the replies left, so a slow
	// sink never delays the client's ack.
	if t.Sandwich.Set {
		ev := nat.SandwichEvent{Role: roleOf(h.Role), Round: t.Sandwich.Round, Phase: t.Sandwich.Phase, Observed: src, At: now}
		queued, panics := e.sandwich.offer(ev, reg.cfg.SandwichQueue)
		if queued {
			st.sandwichEvents.Add(1)
		} else {
			st.sandwichDropped.Add(1)
		}
		st.panics.Add(uint64(panics))
	}
}

// replyPlan is what admit decided under the role lock.
type replyPlan struct {
	ackLen, secLen     int
	ackSeq, auxSeq     uint32
	cookie             uint32
	sendExtra, sendAlt bool
	quota              bool
	wrap               bool // every reply leaves as an opener
}

// admit applies the (session, role) limits to an authentic probe whose
// datagram was size bytes — an opener when wrapped — and, when it is
// accepted, records it in its slot and plans the replies. It returns the
// counter of the limit that refused the probe, or nil. Sealing and sending
// happen after the role lock is released.
func (rd *reader) admit(e *entry, h *udpwire.Header, src netip.AddrPort, now time.Time, mono int64, size int, wrapped bool) (replyPlan, *atomic.Uint64) {
	st, l, cfg := rd.st, rd.l, &rd.s.reg.cfg
	ms := uint32(min(max(now.Sub(e.created)/time.Millisecond, 0), math.MaxUint32))
	altPool := rd.s.altPools[l.fam.Index()]
	rs := &e.roles[h.Role-1]
	rs.mu.Lock()
	defer rs.mu.Unlock()
	switch {
	case rs.unannounced(uint8(h.Aux)):
		return replyPlan{}, &st.badObserver
	case !gcra(&rs.tat, mono, cfg.SessionRate):
		return replyPlan{}, &st.rateSession
	case rs.accepted >= cfg.ProbeBudgetPerRole:
		return replyPlan{}, &st.budget
	case !rs.win.Accept(h.Seq): // after the AEAD: the seq is inside the ciphertext
		return replyPlan{}, &st.replay
	}
	rs.accepted++
	sl := rs.upsert(h.Sock, uint8(h.Aux), l.flags, src, h.Seq, ms, cfg.SlotsPerRole, rd.rng)
	wantExtra := h.FA && !rd.s.cfg.NoExtraReply && rs.extraLeft > 0 && l.pool.usable()
	wantAlt := h.FB && !l.alt && altPool.usable() && rs.altLeft > 0
	var p replyPlan
	p.wrap = wrapped
	p.ackLen, p.secLen = udpwire.ReplyLengths(size, wantExtra || wantAlt, wrapped, rd.rng)
	p.sendExtra, p.sendAlt = wantExtra && p.secLen > 0, wantAlt && p.secLen > 0
	if p.sendExtra {
		rs.extraLeft--
		if sl != nil {
			sl.extraSent = satInc(sl.extraSent)
		}
	}
	if p.sendAlt {
		rs.altLeft--
		if sl != nil {
			sl.altSent = satInc(sl.altSent)
		}
	}
	p.quota = (h.FA && rs.extraLeft == 0) || (h.FB && rs.altLeft == 0)
	p.ackSeq = rs.nextSeq()
	if p.sendExtra || p.sendAlt {
		p.auxSeq = rs.nextSeq()
	}
	if sl != nil {
		p.cookie = sl.cookie
	}
	return p, nil
}

// reply seals and sends the ack and the optional extra or alt to src; the
// ack and the extra leave from dst, the address the probe was sent to, when
// the sockets can name their source.
func (rd *reader) reply(e *entry, h *udpwire.Header, src netip.AddrPort, dst netip.Addr, now time.Time, p replyPlan) {
	st, l := rd.st, rd.l
	if p.ackLen == 0 {
		return // recorded, but L < 83: any reply would outgrow the probe
	}
	var xconn packetConn
	var xmsg msgConn
	var xport uint16
	switch {
	case p.sendExtra:
		xconn, xmsg, xport = l.pool.pick()
	case p.sendAlt:
		xconn, _, _ = rd.s.altPools[l.fam.Index()].pick()
	}
	var from []byte // the reply source's control data
	if dst.IsValid() {
		from = udpsock.AppendSrcAddr(rd.soob[:0], dst)
	}
	ts := uint32(now.UnixMilli())
	ah := udpwire.Header{Type: udpwire.TProbeAck, Role: udpwire.RoleServer, FA: p.sendExtra, FB: p.sendAlt, FC: p.quota,
		Sock: h.Sock, Cand: udpwire.NoCand, Aux: h.Aux, Seq: p.ackSeq, TS: ts, EchoSeq: h.Seq, EchoTS: h.TS}
	at := udpwire.TLVs{Observed: src, ExtraPort: xport, Cookie: p.cookie}
	ack, err := e.codec.Seal(rd.wbuf[:0], &ah, &at, p.ackLen)
	if err != nil {
		st.writeErrs.Add(1)
		return
	}
	if p.wrap {
		ack = e.codec.Wrap(rd.obuf[:0], ack)
	}
	if _, err := rd.write(l.conn, l.msg, ack, from, src); err != nil {
		st.writeErrs.Add(1)
	} else {
		st.acks.Add(1)
		st.bytesOut.Add(uint64(len(ack)))
	}
	if xconn == nil || faultinject.Point(pointExtra) != nil {
		return
	}
	typ := udpwire.TProbeExtra
	if p.sendAlt {
		typ = udpwire.TProbeAlt
	}
	xh := udpwire.Header{Type: typ, Role: udpwire.RoleServer, Sock: h.Sock, Cand: udpwire.NoCand, Aux: h.Aux, Seq: p.auxSeq,
		TS: ts, EchoSeq: h.Seq, EchoTS: h.TS}
	xt := udpwire.TLVs{Observed: src}
	x, err := e.codec.Seal(rd.wbuf[:0], &xh, &xt, p.secLen)
	if err != nil {
		st.writeErrs.Add(1)
		return
	}
	if p.wrap {
		x = e.codec.Wrap(rd.obuf[:0], x)
	}
	if p.sendAlt {
		xmsg = nil // the alt socket is bound to its own address
	}
	if _, err := rd.write(xconn, xmsg, x, from, src); err != nil {
		st.writeErrs.Add(1)
		return
	}
	st.bytesOut.Add(uint64(len(x)))
	if p.sendAlt {
		st.alts.Add(1)
	} else {
		st.extras.Add(1)
	}
}

// write sends b to `to`, from the source in from when the socket can name
// it; a system that refuses that source gets the datagram from the address
// it routes by, which some clients still accept.
func (rd *reader) write(c packetConn, m msgConn, b, from []byte, to netip.AddrPort) (int, error) {
	if m != nil && len(from) > 0 {
		n, _, err := m.WriteMsgUDPAddrPort(b, from, to)
		if err == nil || errors.Is(err, net.ErrClosed) {
			return n, err
		}
		rd.st.srcRefused.Add(1)
	}
	return c.WriteToUDPAddrPort(b, to)
}

// roleOf maps a client header role to the protocol role.
func roleOf(r udpwire.Role) protocol.Role {
	if r == udpwire.RoleResponder {
		return protocol.RoleResponder
	}
	return protocol.RoleInitiator
}
