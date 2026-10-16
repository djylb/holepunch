package holepunch

import (
	"context"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/djylb/holepunch/protocol"
	"github.com/djylb/holepunch/udpwire"
)

// openerRig is a gate rig whose packets land on a listening public host of
// the same simulated network, where the test reads them as they left.
type openerRig struct {
	*gateRig
	dst  []netip.AddrPort
	conn []net.PacketConn
}

func newOpenerRig(t *testing.T, peers int) *openerRig {
	t.Helper()
	fc := fakeClock(t)
	n, h := simHost(t)
	rt := newTestRuntime(t, fc, h)
	s, err := rt.socks.open(context.Background(), protocol.FamilyUDP4, netip.AddrPort{}, PurposeProbe, 0, primaryRecvBuffer)
	if err != nil {
		t.Fatal(err)
	}
	rt.sender.setBudget(bigBudget())
	side := bigSide()
	side.Family = protocol.FamilyUDP4
	m := newRoundMeter(protocol.FamilyUDP4, 1, side, &roundCeiling{ports: 1000})
	rt.sender.startRound(fc.Now(), 1000)
	r := &openerRig{gateRig: &gateRig{t: t, rt: rt, sock: s, m: m, clk: fc}}
	for range peers {
		ph := n.PublicHost(netip.IPv4Unspecified())
		c, err := ph.ListenPacket(context.Background(), "udp4", netip.AddrPortFrom(ph.Addrs()[0], 4000), "test")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = c.Close() })
		r.conn = append(r.conn, c)
		r.dst = append(r.dst, netip.AddrPortFrom(ph.Addrs()[0], 4000))
	}
	return r
}

// next reads the next datagram peer i received and reports whether it came
// as an opener; the packet inside must open with the session codec either
// way.
func (r *openerRig) next(i int) bool {
	r.t.Helper()
	buf := make([]byte, 2048)
	_ = r.conn[i].SetReadDeadline(time.Now().Add(2 * time.Second))
	n, _, err := r.conn[i].ReadFrom(buf)
	if err != nil {
		r.t.Fatalf("peer %d: %v", i, err)
	}
	pkt, wrapped := buf[:n], false
	if udpwire.Wrapped(pkt) {
		inner, e := udpwire.Unwrap(pkt)
		if e != udpwire.OK {
			r.t.Fatalf("peer %d: STUN-range datagram is no opener: %v", i, e)
		}
		pkt, wrapped = inner, true
	}
	if e := r.rt.codec.Open(pkt, nil, nil, nil); e != udpwire.OK {
		r.t.Fatalf("peer %d: packet does not open: %v", i, e)
	}
	return wrapped
}

func (r *openerRig) punch(i int, hops int) {
	r.t.Helper()
	h := udpwire.Header{Type: udpwire.TPunch, Round: 1}
	if err := r.rt.sender.Send(context.Background(), r.sock, r.dst[i], &h, nil,
		sendOpt{class: classInitiate, stage: txDirect, round: r.m, quota: quotaPlan, hops: hops}); err != nil {
		r.t.Fatal(err)
	}
}

// TestOpenerFirstDatagramPerFlow checks the flow opener on the sending side:
// the first datagram of each (socket, remote) flow leaves as an opener and the
// later ones in the plain sealed form, whatever the packet class; the opener
// is one packet of its class for the budget; a third party's STUN request
// leaves as it is.
func TestOpenerFirstDatagramPerFlow(t *testing.T) {
	r := newOpenerRig(t, 2)
	r.punch(0, 0)
	r.punch(0, 0)
	r.punch(1, 0)
	r.punch(0, 0)
	for i, want := range []bool{true, false, false} {
		if got := r.next(0); got != want {
			t.Fatalf("flow 0 datagram %d: opener %v, want %v", i, got, want)
		}
	}
	if !r.next(1) {
		t.Fatal("the first datagram to a second remote is no opener")
	}
	h := udpwire.Header{Type: udpwire.TSuccess}
	if err := r.rt.sender.Send(context.Background(), r.sock, r.dst[1], &h, &udpwire.TLVs{Observed: r.dst[1]},
		sendOpt{class: classReply, stage: txReply}); err != nil {
		t.Fatal(err)
	}
	if r.next(1) {
		t.Fatal("a reply on an opened flow came as an opener")
	}
	fc := r.rt.fam(protocol.FamilyUDP4).cnt.snapshot()
	if fc.TxPackets != 4 || fc.TxOpeners != 2 {
		t.Fatalf("counters: %d initiated, %d openers", fc.TxPackets, fc.TxOpeners)
	}
	if got := r.rt.opener.flows.Load(); got != 2 {
		t.Fatalf("%d flows remembered", got)
	}
}

// TestOpenerLowTTLDoesNotOpen checks that a low-TTL datagram leaves as an
// opener but does not open its flow: it may die before a classifier, so the
// first datagram at the normal TTL is an opener again.
func TestOpenerLowTTLDoesNotOpen(t *testing.T) {
	r := newOpenerRig(t, 1)
	r.punch(0, 2) // dies in the simulated core: nothing arrives
	if _, ok := r.sock.opened[r.dst[0]]; ok {
		t.Fatal("a low-TTL datagram opened the flow")
	}
	r.punch(0, 0)
	r.punch(0, 0)
	if !r.next(0) || r.next(0) {
		t.Fatal("the first normal-TTL datagram after a low-TTL one must be the opener")
	}
	if got := r.rt.fam(protocol.FamilyUDP4).cnt.snapshot().TxOpeners; got != 2 {
		t.Fatalf("%d openers, want 2", got)
	}
}

// TestOpenerSTUNRequestOpens checks that a raw STUN request (the prober's
// sub-probe) is sent unchanged and opens its flow.
func TestOpenerSTUNRequestOpens(t *testing.T) {
	r := newOpenerRig(t, 1)
	req := make([]byte, 20)
	req[1] = 0x01
	copy(req[4:], []byte{0x21, 0x12, 0xA4, 0x42})
	if err := r.rt.sender.SendRaw(context.Background(), r.sock, r.dst[0], req); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 64)
	_ = r.conn[0].SetReadDeadline(time.Now().Add(2 * time.Second))
	n, _, err := r.conn[0].ReadFrom(buf)
	if err != nil || string(buf[:n]) != string(req) {
		t.Fatalf("STUN request changed on the way: % x, %v", buf[:n], err)
	}
	r.punch(0, 0)
	if r.next(0) {
		t.Fatal("the flow a STUN request opened got another opener")
	}
}

// TestOpenerAblationAndBound checks the NoOpener ablation — no opener at all
// — and the session bound on remembered flows: beyond it a flow is opened
// again by its next datagram, never left without an opener.
func TestOpenerAblationAndBound(t *testing.T) {
	r := newOpenerRig(t, 1)
	r.rt.opener.flows.Store(maxOpenFlows)
	r.punch(0, 0)
	r.punch(0, 0)
	for i := range 2 {
		if !r.next(0) {
			t.Fatalf("past the bound, datagram %d of a new flow is no opener", i)
		}
	}
	if len(r.sock.opened) != 0 || r.rt.opener.flows.Load() != maxOpenFlows {
		t.Fatal("a flow was remembered past the bound")
	}
	off := newOpenerRig(t, 1)
	off.sock.op = nil
	off.punch(0, 0)
	if off.next(0) {
		t.Fatal("an opener with the opener off")
	}
}

// TestOpenerReceived checks the receiving side: a peer packet that comes as
// an opener is unwrapped and handled like a plain one; a STUN message that
// is no opener is the prober's (none here: dropped uncounted), and any other
// datagram in the STUN range is foreign.
func TestOpenerReceived(t *testing.T) {
	fc := fakeClock(t)
	_, h := simHost(t)
	rt := newTestRuntime(t, fc, h)
	s, err := rt.socks.open(context.Background(), protocol.FamilyUDP4, netip.AddrPort{}, PurposeProbe, 0, primaryRecvBuffer)
	if err != nil {
		t.Fatal(err)
	}
	peer, err := udpwire.NewCodec(rt.start.Token, rt.start.Wire.RouteID, udpwire.RoleResponder, udpwire.PadPolicy{Min: 60, Max: 160}, nil)
	if err != nil {
		t.Fatal(err)
	}
	ph := udpwire.Header{Type: udpwire.TPunch, Role: udpwire.RoleResponder, Seq: peer.NextSeq(), Cand: udpwire.NoCand}
	pkt, err := peer.Seal(nil, &ph, nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	from := netipAP("198.51.100.9", 7000)
	rt.dispatch(s, peer.Wrap(nil, pkt), from)
	fs := rt.fam(protocol.FamilyUDP4)
	if got := fs.cnt.drops[dropRole].Load() + fs.cnt.drops[dropForeign].Load() + fs.cnt.drops[dropAuth].Load(); got != 0 {
		t.Fatalf("opener dropped (%d)", got)
	}
	verified := fs.cnt.verified.Load()
	bad := peer.Wrap(nil, pkt)
	bad[len(bad)-1] ^= 1
	rt.dispatch(s, bad, from)
	if fs.cnt.drops[dropForeign].Load() != 0 || fs.cnt.verified.Load() != verified {
		t.Fatal("a STUN message that is no opener reached the pipeline")
	}
	junk := append([]byte{0x01}, make([]byte, 99)...)
	rt.dispatch(s, junk, from)
	if fs.cnt.drops[dropForeign].Load() != 1 {
		t.Fatal("a STUN-range datagram that is no STUN message is not foreign")
	}
}
