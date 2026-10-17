package holepunch

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/djylb/holepunch/internal/udpwire"
	"github.com/djylb/holepunch/protocol"
)

// udpPeer plays the other client over raw UDP with the session's keys, so a
// test can drive the handshake packet by packet.
type udpPeer struct {
	t     *testing.T
	conn  net.PacketConn
	codec *udpwire.Codec
	addr  netip.AddrPort
	pkts  chan peerPkt
	done  chan struct{}
}

type peerPkt struct {
	h    udpwire.Header
	from netip.AddrPort
}

func newUDPPeer(t *testing.T, w *world, s *session, role protocol.Role, token protocol.Token) *udpPeer {
	t.Helper()
	h := w.host(nil)
	conn, err := h.ListenPacket(context.Background(), "udp4", netip.AddrPortFrom(h.Addrs()[0], 0), "test")
	if err != nil {
		t.Fatal(err)
	}
	codec, err := udpwire.NewCodec(token, s.wire.RouteID, udpwire.Role(role.Code()),
		udpwire.PadPolicy{Min: s.wire.PayloadMin, Max: s.wire.PayloadMax}, nil)
	if err != nil {
		t.Fatal(err)
	}
	p := &udpPeer{t: t, conn: conn, codec: codec, pkts: make(chan peerPkt, 1024), done: make(chan struct{})}
	p.addr = netip.AddrPortFrom(h.Addrs()[0], uint16(conn.LocalAddr().(*net.UDPAddr).Port))
	go p.read()
	t.Cleanup(p.close)
	return p
}

func (p *udpPeer) read() {
	defer close(p.done)
	buf := make([]byte, 2048)
	for {
		n, a, err := p.conn.ReadFrom(buf)
		if err != nil {
			return
		}
		pkt := buf[:n]
		if udpwire.Wrapped(pkt) {
			inner, e := udpwire.Unwrap(pkt) // the first datagram of each flow
			if e != udpwire.OK {
				continue
			}
			pkt = inner
		}
		var h udpwire.Header
		if p.codec.Open(pkt, nil, &h, nil) != udpwire.OK || p.codec.CheckRole(&h) != udpwire.OK {
			continue
		}
		select {
		case p.pkts <- peerPkt{h, a.(*net.UDPAddr).AddrPort()}:
		default:
		}
	}
}

func (p *udpPeer) close() {
	_ = p.conn.Close()
	<-p.done
}

// send seals h (and t) and writes it to `to`.
func (p *udpPeer) send(to netip.AddrPort, h udpwire.Header, t *udpwire.TLVs) {
	h.Role = p.codec.Role()
	h.Seq = p.codec.NextSeq()
	h.TS = p.codec.Now()
	pkt, err := p.codec.Seal(nil, &h, t, 0)
	if err != nil {
		p.t.Errorf("seal %v: %v", h.Type, err)
		return
	}
	_, _ = p.conn.WriteTo(pkt, net.UDPAddrFromAddrPort(to))
}

// expect returns the next packet of type typ.
func (p *udpPeer) expect(typ udpwire.Type, d time.Duration) (peerPkt, bool) {
	t := time.NewTimer(d)
	defer t.Stop()
	for {
		select {
		case pk := <-p.pkts:
			if pk.h.Type == typ {
				return pk, true
			}
		case <-t.C:
			return peerPkt{}, false
		}
	}
}

// fakeView is a verified peer view of the udpPeer.
func (p *udpPeer) view() protocol.PeerView {
	return fakePeer(p.addr.String())
}

// soloWithPeer runs a public client (role r) up to its first go towards a
// udpPeer, and returns both.
func soloWithPeer(t *testing.T, r protocol.Role, token func(*session) protocol.Token, to protocol.Timeouts, tweak ...func(*Options)) (*solo, *udpPeer, protocol.PeerView) {
	t.Helper()
	w := newWorld(t)
	so := newSolo(t, w, nil, func(o *Options) {
		for _, f := range tweak {
			f(o)
		}
	})
	so.role = r
	tok := so.s.token
	if token != nil {
		tok = token(so.s)
	}
	peer := newUDPPeer(t, w, so.s, r.Peer(), tok)
	so.start(to)
	_, self := so.report()
	r1 := so.summary(self, peer.view(), to)
	if _, ok := so.link.next(5*time.Second, protocol.MsgPunchReady); !ok {
		t.Fatal("no ready")
	}
	so.link.send(protocol.PunchGo{SessionID: so.s.sid, Round: 1, DelayMs: 5, WindowMs: r1.WindowMs})
	return so, peer, self
}

// clientAddr is the client's verified public endpoint.
func clientAddr(self protocol.PeerView) netip.AddrPort {
	return self.Families[0].Endpoints[0].Addr
}

// The fake responder answers the punches and accepts the nomination; the
// client hands over on the fake's handshake behaviour.
func TestInitiatorHandoverEvidence(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name   string
		onRdy  func(p *udpPeer, to netip.AddrPort, e uint16)
		by     protocol.HandoverEvidence
		reason protocol.Reason
	}{
		{"ack", func(p *udpPeer, to netip.AddrPort, e uint16) {
			for range 3 {
				p.send(to, udpwire.Header{Type: udpwire.THandoverAck, Aux: e, Cand: udpwire.NoCand}, &udpwire.TLVs{HasRx: true, RxCount: 1})
			}
		}, protocol.ConfirmedByAck, ""},
		{"upper_layer", func(p *udpPeer, to netip.AddrPort, _ uint16) {
			_, _ = p.conn.WriteTo([]byte{0x40, 1, 2, 3, 4, 5, 6, 7, 8}, net.UDPAddrFromAddrPort(to))
		}, protocol.ConfirmedByUpperLayer, ""},
		{"quiet", func(*udpPeer, netip.AddrPort, uint16) {}, protocol.ConfirmedByQuiet, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			so, peer, self := soloWithPeer(t, protocol.RoleInitiator, nil, testTimeouts())
			me := clientAddr(self)
			pk, ok := peer.expect(udpwire.TPunch, 5*time.Second)
			if !ok {
				t.Fatal("no punch")
			}
			peer.send(pk.from, udpwire.Header{Type: udpwire.TSuccess, Round: 1, Cand: pk.h.Cand, EchoSeq: pk.h.Seq, EchoTS: pk.h.TS},
				&udpwire.TLVs{Observed: pk.from, HasRx: true, RxCount: 1})
			nom, ok := peer.expect(udpwire.TNominate, 5*time.Second)
			if !ok {
				t.Fatal("no nominate")
			}
			peer.send(nom.from, udpwire.Header{Type: udpwire.TAccept, Aux: nom.h.Aux, Cand: udpwire.NoCand}, &udpwire.TLVs{HasRx: true, RxCount: 2})
			if _, ok := peer.expect(udpwire.TReady, 5*time.Second); !ok {
				t.Fatal("no ready")
			}
			c.onRdy(peer, nom.from, nom.h.Aux)
			m, ok := so.link.next(5*time.Second, protocol.MsgRoundResult)
			if !ok || m.(*protocol.RoundResult).Status != protocol.RoundConfirmed || m.(*protocol.RoundResult).Path == nil {
				t.Fatalf("round_result %+v", m)
			}
			r := so.result(5 * time.Second)
			if r.err != nil {
				t.Fatal(r.err)
			}
			defer func() { _ = r.sess.Close() }()
			if got := r.sess.Diagnostics().Path.ConfirmedBy; got != c.by {
				t.Fatalf("confirmed by %s, want %s", got, c.by)
			}
			if r.sess.Result().Path.RemoteAddr != peer.addr || r.sess.Result().Path.LocalAddr != me {
				t.Fatalf("result %+v", r.sess.Result())
			}
			if err := so.track.CheckOpen(1); err != nil {
				t.Fatal(err)
			}
		})
	}
}

// Handover timeout: the responder keeps accepting and never acknowledges
// ready, so neither ack nor quiet completes the handover: handover_timeout,
// and the winner is closed.
func TestHandoverTimeout(t *testing.T) {
	t.Parallel()
	to := testTimeouts()
	to.HandoverTimeoutMs = 800
	so, peer, _ := soloWithPeer(t, protocol.RoleInitiator, nil, to)
	pk, ok := peer.expect(udpwire.TPunch, 5*time.Second)
	if !ok {
		t.Fatal("no punch")
	}
	peer.send(pk.from, udpwire.Header{Type: udpwire.TSuccess, Round: 1, Cand: pk.h.Cand, EchoSeq: pk.h.Seq, EchoTS: pk.h.TS},
		&udpwire.TLVs{Observed: pk.from, HasRx: true, RxCount: 1})
	nom, ok := peer.expect(udpwire.TNominate, 5*time.Second)
	if !ok {
		t.Fatal("no nominate")
	}
	stop := make(chan struct{})
	go func() {
		tk := time.NewTicker(40 * time.Millisecond)
		defer tk.Stop()
		for {
			peer.send(nom.from, udpwire.Header{Type: udpwire.TAccept, Aux: nom.h.Aux, Cand: udpwire.NoCand}, &udpwire.TLVs{HasRx: true, RxCount: 2})
			select {
			case <-tk.C:
			case <-stop:
				return
			}
		}
	}()
	defer close(stop)
	pr := so.punchResult()
	if pr.Reason != protocol.ReasonHandoverTimeout || pr.Phase != protocol.PhaseHandover {
		t.Fatalf("punch_result %+v", pr)
	}
	e := so.wantError(so.result(5*time.Second), protocol.ReasonHandoverTimeout)
	if e.Phase != protocol.PhaseHandover {
		t.Fatalf("phase %s", e.Phase)
	}
}

// The responder side: adopt the nomination, confirm on ready, burst acks,
// hand over by ready; an upper-layer packet after accept also completes it.
func TestResponderHandover(t *testing.T) {
	t.Parallel()
	for _, c := range []struct {
		name string
		by   protocol.HandoverEvidence
	}{{"ready", protocol.ConfirmedByReady}, {"upper_layer", protocol.ConfirmedByUpperLayer}} {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			so, peer, self := soloWithPeer(t, protocol.RoleResponder, nil, testTimeouts())
			me := clientAddr(self)
			for range 3 {
				peer.send(me, udpwire.Header{Type: udpwire.TPunch, Round: 1, Cand: 1}, nil)
			}
			if _, ok := peer.expect(udpwire.TSuccess, 5*time.Second); !ok {
				t.Fatal("no success")
			}
			peer.send(me, udpwire.Header{Type: udpwire.TNominate, Aux: 1, Cand: udpwire.NoCand}, nil)
			acc, ok := peer.expect(udpwire.TAccept, 5*time.Second)
			if !ok || acc.h.Aux != 1 {
				t.Fatalf("accept %+v", acc)
			}
			if c.by == protocol.ConfirmedByReady {
				peer.send(me, udpwire.Header{Type: udpwire.TReady, Aux: 1, Cand: udpwire.NoCand}, nil)
				if _, ok := peer.expect(udpwire.THandoverAck, 5*time.Second); !ok {
					t.Fatal("no handover_ack")
				}
			} else {
				_, _ = peer.conn.WriteTo([]byte{0x41, 9, 9, 9, 9, 9}, net.UDPAddrFromAddrPort(me))
			}
			r := so.result(5 * time.Second)
			if r.err != nil {
				t.Fatal(r.err)
			}
			defer func() { _ = r.sess.Close() }()
			if got := r.sess.Diagnostics().Path.ConfirmedBy; got != c.by {
				t.Fatalf("confirmed by %s", got)
			}
		})
	}
}

// Packets from the peer's verified IP that fail authentication, and no
// valid packet at all: token_mismatch.
func TestTokenMismatch(t *testing.T) {
	t.Parallel()
	to := testTimeouts()
	to.GoWaitMs = 500
	so, peer, self := soloWithPeer(t, protocol.RoleInitiator, func(*session) protocol.Token { return protocol.NewToken() }, to)
	me := clientAddr(self)
	for range 5 {
		peer.send(me, udpwire.Header{Type: udpwire.TPunch, Round: 1, Cand: 1}, nil)
	}
	e := so.wantError(so.result(10*time.Second), protocol.ReasonTokenMismatch)
	if e.Diagnostics.Counters.TokenMismatch < tokenMismatchMin || e.Diagnostics.Counters.Drops[protocol.DropAuth] < tokenMismatchMin {
		t.Fatalf("counters %+v", e.Diagnostics.Counters)
	}
}

// peer_seen after the peer heard us, with nothing heard back: the follow-up
// repeats the exact pair, and the session ends one-way.
func TestPeerSeenOneWay(t *testing.T) {
	t.Parallel()
	to := testTimeouts()
	to.GoWaitMs = 500
	so, peer, _ := soloWithPeer(t, protocol.RoleInitiator, nil, to)
	pk, ok := peer.expect(udpwire.TPunch, 5*time.Second)
	if !ok {
		t.Fatal("no punch")
	}
	so.link.send(protocol.Assist{SessionID: so.s.sid, From: protocol.RoleResponder, Kind: protocol.AssistPeerSeen, Round: 1,
		Family: protocol.FamilyUDP4, Remote: pk.from, Sock: pk.h.Sock, Cand: pk.h.Cand, Type: uint8(udpwire.TPunch), First: true})
	e := so.wantError(so.result(10*time.Second), protocol.ReasonOneWayUDPOnly)
	if e.Detail != "peer_hears_us" || !e.Diagnostics.Counters.PeerSeenUs {
		t.Fatalf("error %+v", e)
	}
}

// brokenReads is a Network whose sockets fail reading once broken is set.
type brokenReads struct {
	Network
	broken *atomic.Bool
}

func (b brokenReads) ListenPacket(ctx context.Context, network string, laddr netip.AddrPort, purpose string) (net.PacketConn, error) {
	c, err := b.Network.ListenPacket(ctx, network, laddr, purpose)
	if err != nil {
		return nil, err
	}
	return brokenConn{c, b.broken}, nil
}

type brokenConn struct {
	net.PacketConn
	broken *atomic.Bool
}

func (c brokenConn) ReadFrom(p []byte) (int, net.Addr, error) {
	n, a, err := c.PacketConn.ReadFrom(p)
	if c.broken.Load() {
		return 0, nil, errors.New("read path broken")
	}
	return n, a, err
}

// Once the winning socket fails reading, silence is no handover
// evidence; without an ack the initiator ends at the handover timeout.
func TestReadFailedNoQuiet(t *testing.T) {
	t.Parallel()
	to := testTimeouts()
	to.HandoverTimeoutMs = 800
	var broken atomic.Bool
	so, peer, _ := soloWithPeer(t, protocol.RoleInitiator, nil, to, func(o *Options) {
		o.Network = brokenReads{o.Network, &broken}
	})
	pk, ok := peer.expect(udpwire.TPunch, 5*time.Second)
	if !ok {
		t.Fatal("no punch")
	}
	peer.send(pk.from, udpwire.Header{Type: udpwire.TSuccess, Round: 1, Cand: pk.h.Cand, EchoSeq: pk.h.Seq, EchoTS: pk.h.TS},
		&udpwire.TLVs{Observed: pk.from, HasRx: true, RxCount: 1})
	nom, ok := peer.expect(udpwire.TNominate, 5*time.Second)
	if !ok {
		t.Fatal("no nominate")
	}
	peer.send(nom.from, udpwire.Header{Type: udpwire.TAccept, Aux: nom.h.Aux, Cand: udpwire.NoCand}, &udpwire.TLVs{HasRx: true, RxCount: 2})
	if _, ok := peer.expect(udpwire.TReady, 5*time.Second); !ok {
		t.Fatal("no ready")
	}
	broken.Store(true)
	peer.send(nom.from, udpwire.Header{Type: udpwire.TAccept, Aux: nom.h.Aux, Cand: udpwire.NoCand}, nil) // wakes the read
	e := so.wantError(so.result(5*time.Second), protocol.ReasonHandoverTimeout)
	if e.Phase != protocol.PhaseHandover {
		t.Fatalf("phase %s", e.Phase)
	}
}
