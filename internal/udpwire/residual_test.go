package udpwire

import (
	"bytes"
	"errors"
	"io"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"
)

// residualFixture is a responder-side listener after handover: its codec is
// bound to the initiator's address.
type residualFixture struct {
	clk     *manualClock
	ini     *Codec // the remote side, source of residuals
	resp    *Codec // the codec given to DropResidual
	counter *countingAEAD
	conn    *queueConn
	peer    *net.UDPAddr
}

func newResidualFixture(t *testing.T) *residualFixture {
	t.Helper()
	f := &residualFixture{clk: newManualClock(), conn: &queueConn{}, peer: udpAddr("203.0.113.5:40000")}
	var err error
	f.resp, err = NewCodec(testToken(), testRoute(), RoleResponder, testPad, f.clk.Now)
	if err != nil {
		t.Fatal(err)
	}
	f.counter = &countingAEAD{AEAD: f.resp.aead}
	f.resp.aead = f.counter
	f.resp.BindPeers(f.peer.AddrPort())
	f.ini = newCodec(t, RoleInitiator)
	return f
}

// residual returns a sealed ready retransmission from the initiator.
func (f *residualFixture) residual(t *testing.T) []byte {
	t.Helper()
	h := headerFor(f.ini, TReady)
	h.Retx = true
	return mustSeal(t, f.ini, &h, nil)
}

// readAll drains pc and returns what the upper layer sees.
func readAll(t *testing.T, pc net.PacketConn) []datagram {
	t.Helper()
	var out []datagram
	buf := make([]byte, 2048)
	for {
		n, from, err := pc.ReadFrom(buf)
		if errors.Is(err, io.EOF) {
			return out
		}
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, datagram{data: bytes.Clone(buf[:n]), from: from})
	}
}

func TestDropResidualWindow(t *testing.T) {
	f := newResidualFixture(t)
	pc := DropResidual(f.conn, f.resp, 5*time.Second)

	upperInRange := bytes.Repeat([]byte{0x05, 0x99}, 50) // KCP-like payload whose first byte is in range
	upperQUIC := bytes.Repeat([]byte{0x80}, 60)
	other := udpAddr("198.51.100.1:40000")
	mapped := &net.UDPAddr{IP: f.peer.IP.To16(), Port: f.peer.Port} // same peer, 16-byte IPv4 form
	residual := f.residual(t)
	f.conn.push(f.residual(t), f.peer)
	f.conn.push(upperInRange, f.peer)
	f.conn.push(f.residual(t), mapped)
	f.conn.push(upperQUIC, f.peer)
	f.conn.push(residual, other)
	f.conn.push(residual[:MinPeerPacket-1], f.peer)
	f.conn.push(f.residual(t), f.peer)

	got := readAll(t, pc)
	want := []datagram{{upperInRange, f.peer}, {upperQUIC, f.peer}, {residual, other}, {residual[:MinPeerPacket-1], f.peer}}
	if len(got) != len(want) {
		t.Fatalf("upper layer saw %d datagrams, want %d", len(got), len(want))
	}
	for i := range want {
		if !bytes.Equal(got[i].data, want[i].data) || got[i].from.String() != want[i].from.String() {
			t.Errorf("datagram %d: %x from %v", i, got[i].data, got[i].from)
		}
	}
	// Only the datagrams from the peer with a valid length and b0 were
	// trial-opened: three residuals and upperInRange.
	if n := f.counter.count(); n != 4 {
		t.Errorf("AEAD trial opens = %d, want 4", n)
	}

	// After the window everything passes and the AEAD is never consulted.
	f.clk.Advance(5 * time.Second)
	before := f.counter.count()
	for range 3 {
		f.conn.push(f.residual(t), f.peer)
	}
	if got := readAll(t, pc); len(got) != 3 {
		t.Fatalf("after the window %d of 3 datagrams passed", len(got))
	}
	if f.counter.count() != before {
		t.Error("AEAD used after the window")
	}
}

func TestDropResidualDefaultsAndDelegation(t *testing.T) {
	f := newResidualFixture(t)
	if DropResidual(f.conn, nil, time.Second) != net.PacketConn(f.conn) {
		t.Error("nil codec must return pc itself")
	}
	if DropResidual(nil, f.resp, time.Second) != nil {
		t.Error("nil pc must return nil")
	}

	pc := DropResidual(f.conn, f.resp, 0)
	f.clk.Advance(DefaultResidualWindow - time.Millisecond)
	f.conn.push(f.residual(t), f.peer)
	if got := readAll(t, pc); len(got) != 0 {
		t.Error("default window should still filter just before it ends")
	}
	f.clk.Advance(time.Millisecond)
	f.conn.push(f.residual(t), f.peer)
	if got := readAll(t, pc); len(got) != 1 {
		t.Error("default window should end after DefaultResidualWindow")
	}

	if pc.LocalAddr().String() != f.conn.LocalAddr().String() {
		t.Error("LocalAddr not delegated")
	}
	if err := pc.Close(); err != nil || !f.conn.isClosed() {
		t.Error("Close not delegated")
	}
}

// stringAddr is a net.Addr that is not a *net.UDPAddr.
type stringAddr string

func (a stringAddr) Network() string { return "udp" }
func (a stringAddr) String() string  { return string(a) }

// addrPortAddr is a net.Addr with an AddrPort method, as simulated networks
// provide.
type addrPortAddr struct{ ap netip.AddrPort }

func (a addrPortAddr) Network() string          { return "udp" }
func (a addrPortAddr) String() string           { return a.ap.String() }
func (a addrPortAddr) AddrPort() netip.AddrPort { return a.ap }

func TestDropResidualSources(t *testing.T) {
	f := newResidualFixture(t)
	pc := DropResidual(f.conn, f.resp, time.Minute)
	f.conn.push(f.residual(t), stringAddr(f.peer.String()))           // other Addr type, same peer
	f.conn.push(f.residual(t), addrPortAddr{f.peer.AddrPort()})       // AddrPort method, same peer
	f.conn.push(f.residual(t), udpAddr("[::ffff:203.0.113.5]:40000")) // same peer, v4-mapped
	f.conn.push(f.residual(t), stringAddr("not an address"))
	f.conn.push(f.residual(t), nil)
	f.conn.push(f.residual(t), (*net.UDPAddr)(nil))
	if got := readAll(t, pc); len(got) != 3 {
		t.Fatalf("got %d datagrams, want the 3 without a usable source", len(got))
	}
	if n := pc.(interface{ Dropped() uint64 }).Dropped(); n != 3 {
		t.Errorf("Dropped() = %d, want 3", n)
	}

	// Before BindPeers there is no confirmed remote to compare with, so the AEAD
	// alone decides, for any source.
	unbound := newCodec(t, RoleResponder)
	conn := &queueConn{}
	conn.push(f.residual(t), udpAddr("192.0.2.200:1"))
	conn.push(f.residual(t), nil)
	conn.push([]byte("upper layer"), udpAddr("192.0.2.200:1"))
	if got := readAll(t, DropResidual(conn, unbound, time.Minute)); len(got) != 1 {
		t.Errorf("unbound codec passed %d datagrams, want only the upper-layer one", len(got))
	}
}

func TestDropResidualConcurrentReaders(t *testing.T) {
	f := newResidualFixture(t)
	pc := DropResidual(f.conn, f.resp, time.Minute)
	const total = 400
	for i := range total {
		if i%2 == 0 {
			f.conn.push(f.residual(t), f.peer)
		} else {
			f.conn.push([]byte{byte(i)}, f.peer)
		}
	}
	var mu sync.Mutex
	passed := 0
	var wg sync.WaitGroup
	for range 4 {
		wg.Go(func() {
			buf := make([]byte, 2048)
			for {
				_, _, err := pc.ReadFrom(buf)
				if err != nil {
					return
				}
				mu.Lock()
				passed++
				mu.Unlock()
			}
		})
	}
	wg.Wait()
	if passed != total/2 {
		t.Errorf("%d datagrams passed, want %d", passed, total/2)
	}
}
