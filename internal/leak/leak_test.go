package leak

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"go.uber.org/goleak"
)

func TestMain(m *testing.M) {
	goleak.VerifyTestMain(m)
}

// udpNetwork opens real loopback UDP sockets.
type udpNetwork struct{}

func (udpNetwork) ListenPacket(_ context.Context, network string, laddr netip.AddrPort, _ string) (net.PacketConn, error) {
	return net.ListenUDP(network, net.UDPAddrFromAddrPort(laddr))
}
func (udpNetwork) InterfaceAddrs() ([]net.Interface, [][]netip.Prefix, error) {
	lo := net.Interface{Index: 1, MTU: 16384, Name: "lo0", Flags: net.FlagUp | net.FlagLoopback}
	return []net.Interface{lo}, [][]netip.Prefix{{netip.MustParsePrefix("127.0.0.1/8")}}, nil
}
func (udpNetwork) OutboundAddr(context.Context, string) (netip.Addr, error) {
	return netip.MustParseAddr("127.0.0.1"), nil
}
func (udpNetwork) LookupNetIP(_ context.Context, _, host string) ([]netip.Addr, error) {
	return []netip.Addr{netip.MustParseAddr("127.0.0.2")}, errors.New(host)
}

// funcNetwork returns whatever listen returns.
type funcNetwork struct {
	udpNetwork
	listen func() (net.PacketConn, error)
}

func (n funcNetwork) ListenPacket(context.Context, string, netip.AddrPort, string) (net.PacketConn, error) {
	return n.listen()
}

var loopback = netip.MustParseAddrPort("127.0.0.1:0")

func TestTrackingCountsPerPurpose(t *testing.T) {
	tn := NewTrackingNetwork(udpNetwork{})
	ctx := context.Background()
	listen := func(purpose string) net.PacketConn {
		t.Helper()
		pc, err := tn.ListenPacket(ctx, "udp4", loopback, purpose)
		if err != nil {
			t.Fatal(err)
		}
		return pc
	}
	p1, p2, w := listen("probe"), listen("probe"), listen("warmup")

	if err := p1.Close(); err != nil {
		t.Fatal(err)
	}
	if err := p1.Close(); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("second Close = %v, want the inner conn's net.ErrClosed", err)
	}
	st := tn.Stats()
	got := st.ByPurpose
	if got["probe"] != (Count{Opened: 2, Closed: 1}) || got["warmup"] != (Count{Opened: 1}) || len(got) != 2 {
		t.Fatalf("ByPurpose = %v", got)
	}
	if st.Total != (Count{Opened: 3, Closed: 1}) || st.Total.Open() != 2 || tn.Open() != 2 {
		t.Fatalf("Total = %v, Open = %d", st.Total, tn.Open())
	}
	if err := tn.CheckOpen(2); err != nil {
		t.Fatalf("CheckOpen(2) = %v", err)
	}
	want := fmt.Sprintf("leak: 2 sockets open, want 1: [#2 probe udp4 %s; #3 warmup udp4 %s]", p2.LocalAddr(), w.LocalAddr())
	if err := tn.CheckOpen(1); err == nil || err.Error() != want {
		t.Fatalf("CheckOpen(1) = %v\nwant %s", err, want)
	}
	if tn.CheckClosed() == nil {
		t.Fatal("CheckClosed passed with sockets open")
	}
	_ = p2.Close()
	_ = w.Close()
	if err := tn.CheckClosed(); err != nil {
		t.Fatalf("CheckClosed = %v", err)
	}
}

func TestFailedAndNilListensCountAsFailed(t *testing.T) {
	boom := errors.New("bind failed")
	var typedNil *net.UDPConn
	for _, tc := range []struct {
		name   string
		listen func() (net.PacketConn, error)
		check  func(net.PacketConn, error) bool
	}{
		{"error", func() (net.PacketConn, error) { return nil, boom }, func(pc net.PacketConn, err error) bool { return pc == nil && errors.Is(err, boom) }},
		{"nil", func() (net.PacketConn, error) { return nil, nil }, func(pc net.PacketConn, err error) bool { return pc == nil && err == nil }},
		{"typed nil", func() (net.PacketConn, error) { return typedNil, nil }, func(pc net.PacketConn, err error) bool {
			u, ok := pc.(*net.UDPConn)
			return ok && u == nil && err == nil
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tn := NewTrackingNetwork(funcNetwork{listen: tc.listen})
			pc, err := tn.ListenPacket(context.Background(), "udp4", loopback, "probe")
			if !tc.check(pc, err) {
				t.Fatalf("ListenPacket = (%#v, %v), want the inner result unchanged", pc, err)
			}
			if st := tn.Stats(); st.Total != (Count{Failed: 1}) || st.ByPurpose["probe"] != (Count{Failed: 1}) || tn.Open() != 0 {
				t.Fatalf("Stats = %+v, want one failure", st)
			}
		})
	}
}

func TestDelegation(t *testing.T) {
	tn := NewTrackingNetwork(udpNetwork{})
	ctx := context.Background()
	if ifs, p, err := tn.InterfaceAddrs(); err != nil || len(ifs) != 1 || ifs[0].Name != "lo0" || len(p) != 1 || len(p[0]) != 1 {
		t.Fatalf("InterfaceAddrs = %v, %v, %v", ifs, p, err)
	}
	if a, err := tn.OutboundAddr(ctx, "udp4"); err != nil || a != netip.MustParseAddr("127.0.0.1") {
		t.Fatalf("OutboundAddr = %v, %v", a, err)
	}
	if a, err := tn.LookupNetIP(ctx, "ip4", "example.test"); len(a) != 1 || err == nil || err.Error() != "example.test" {
		t.Fatalf("LookupNetIP = %v, %v", a, err)
	}

	empty := NewTrackingNetwork(nil)
	_, e1 := empty.ListenPacket(ctx, "udp4", loopback, "probe")
	_, _, e2 := empty.InterfaceAddrs()
	_, e3 := empty.OutboundAddr(ctx, "udp4")
	_, e4 := empty.LookupNetIP(ctx, "ip4", "x")
	for _, err := range []error{e1, e2, e3, e4} {
		if !errors.Is(err, errNoInner) {
			t.Fatalf("nil inner returned %v", err)
		}
	}
}

// fakeConn is a PacketConn without optional capabilities.
type fakeConn struct{}

func (fakeConn) ReadFrom([]byte) (int, net.Addr, error)    { return 0, nil, net.ErrClosed }
func (fakeConn) WriteTo(p []byte, _ net.Addr) (int, error) { return len(p), nil }
func (fakeConn) Close() error                              { return nil }
func (fakeConn) LocalAddr() net.Addr                       { return nil }
func (fakeConn) SetDeadline(time.Time) error               { return nil }
func (fakeConn) SetReadDeadline(time.Time) error           { return nil }
func (fakeConn) SetWriteDeadline(time.Time) error          { return nil }
func (fakeConn) ReadFromUDPAddrPort([]byte) (int, netip.AddrPort, error) {
	return 0, netip.AddrPort{}, net.ErrClosed
}
func (fakeConn) WriteToUDPAddrPort(p []byte, _ netip.AddrPort) (int, error) { return len(p), nil }

// capRecorder implements every optional capability and records the calls.
type capRecorder struct {
	calls []string
}

func (r *capRecorder) SetHopLimit(int) error { r.calls = append(r.calls, "hop"); return nil }
func (r *capRecorder) SyscallConn() (syscall.RawConn, error) {
	r.calls = append(r.calls, "sys")
	return nil, errors.ErrUnsupported
}
func (r *capRecorder) SetReadBuffer(int) error  { r.calls = append(r.calls, "rbuf"); return nil }
func (r *capRecorder) SetWriteBuffer(int) error { r.calls = append(r.calls, "wbuf"); return nil }

// TestCapabilitiesMirrorInner checks all 16 combinations: the tracked conn
// implements an optional interface exactly when the inner conn does, and the
// call reaches the inner implementation.
func TestCapabilitiesMirrorInner(t *testing.T) {
	names := []string{"hop", "sys", "rbuf", "wbuf"}
	for mask := range 16 {
		rec := &capRecorder{}
		var caps capabilities
		if mask&1 != 0 {
			caps.hop = rec
		}
		if mask&2 != 0 {
			caps.sys = rec
		}
		if mask&4 != 0 {
			caps.rbuf = rec
		}
		if mask&8 != 0 {
			caps.wbuf = rec
		}
		inner := withCapabilities(fakeConn{}, caps)
		tn := NewTrackingNetwork(funcNetwork{listen: func() (net.PacketConn, error) { return inner, nil }})
		pc, err := tn.ListenPacket(context.Background(), "udp4", loopback, "probe")
		if err != nil {
			t.Fatal(err)
		}
		var want []string
		for bit, name := range names {
			has := false
			switch name {
			case "hop":
				if h, ok := pc.(HopLimiter); ok {
					has = true
					_ = h.SetHopLimit(1)
				}
			case "sys":
				if s, ok := pc.(syscall.Conn); ok {
					has = true
					_, _ = s.SyscallConn()
				}
			case "rbuf":
				if b, ok := pc.(readBufferSetter); ok {
					has = true
					_ = b.SetReadBuffer(1)
				}
			case "wbuf":
				if b, ok := pc.(writeBufferSetter); ok {
					has = true
					_ = b.SetWriteBuffer(1)
				}
			}
			if has != (mask&(1<<bit) != 0) {
				t.Fatalf("mask %04b: tracked conn has %s = %v", mask, name, has)
			}
			if has {
				want = append(want, name)
			}
		}
		if strings.Join(rec.calls, ",") != strings.Join(want, ",") {
			t.Fatalf("mask %04b: inner saw calls %v, want %v", mask, rec.calls, want)
		}
		if pc == any(inner) {
			t.Fatalf("mask %04b: conn was not wrapped", mask)
		}
		if oc := tn.OpenConns(); len(oc) != 1 || oc[0].Local != "?" {
			t.Fatalf("mask %04b: OpenConns = %v, want one conn with an unknown local address", mask, oc)
		}
		_ = pc.Close()
		if err := tn.CheckClosed(); err != nil {
			t.Fatalf("mask %04b: %v", mask, err)
		}
	}
}

func TestUDPConnCapabilitiesAndComparability(t *testing.T) {
	tn := NewTrackingNetwork(udpNetwork{})
	a, err := tn.ListenPacket(context.Background(), "udp4", loopback, "probe")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = a.Close() }()
	b, err := tn.ListenPacket(context.Background(), "udp4", loopback, "probe")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = b.Close() }()
	if _, ok := a.(HopLimiter); ok {
		t.Fatal("*net.UDPConn has no SetHopLimit, the tracked conn must not either")
	}
	if _, ok := a.(syscall.Conn); !ok {
		t.Fatal("tracked UDP conn lost syscall.Conn")
	}
	if err := a.(readBufferSetter).SetReadBuffer(1 << 16); err != nil {
		t.Fatal(err)
	}
	if err := a.(writeBufferSetter).SetWriteBuffer(1 << 16); err != nil {
		t.Fatal(err)
	}
	if _, ok := a.(*net.UDPConn); ok {
		t.Fatal("tracked conn exposes the concrete type")
	}
	set := map[net.PacketConn]bool{a: true}
	if a == b || !set[a] || set[b] {
		t.Fatal("tracked conns do not compare by identity")
	}
	// Traffic passes through the wrapper.
	if _, err := a.WriteTo([]byte("x"), b.LocalAddr()); err != nil {
		t.Fatal(err)
	}
	if err := b.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 8)
	if n, _, err := b.ReadFrom(buf); err != nil || string(buf[:n]) != "x" {
		t.Fatalf("ReadFrom = %q, %v", buf[:n], err)
	}
}

func TestConcurrentOpenClose(t *testing.T) {
	tn := NewTrackingNetwork(udpNetwork{})
	var wg, closers sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 25 {
				pc, err := tn.ListenPacket(context.Background(), "udp4", loopback, "birthday")
				if err != nil {
					t.Error(err)
					return
				}
				closers.Go(func() { _ = pc.Close() })
				_ = tn.Open()
				_ = tn.Stats()
				_ = tn.OpenConns()
			}
		}()
	}
	wg.Wait()
	// The tracker counts a Close before the wrapped conn closes: wait for
	// every Close to return, so that no descriptor of this test is still
	// open when the next one counts them.
	closers.Wait()
	if c := tn.Stats().ByPurpose["birthday"]; c != (Count{Opened: 200, Closed: 200}) {
		t.Fatalf("Counts = %v", c)
	}
}

func TestOpenFDsAndCheckFDs(t *testing.T) {
	// Warm up the network poller, whose descriptors are created on first use.
	if warm, err := net.ListenUDP("udp4", nil); err == nil {
		_ = warm.Close()
	}
	base, err := OpenFDs()
	if errors.Is(err, errors.ErrUnsupported) {
		t.Skip(err) // descriptors are counted on darwin and linux only
	}
	if err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatal(err)
	}
	pc, err := net.ListenUDP("udp4", net.UDPAddrFromAddrPort(loopback))
	if err != nil {
		t.Fatal(err)
	}
	if n, _ := OpenFDs(); n != base+2 {
		t.Fatalf("OpenFDs = %d after opening a file and a socket, want %d", n, base+2)
	}

	short, cancelShort := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancelShort()
	if err := CheckFDs(short, base); err == nil || !strings.Contains(err.Error(), "file descriptors open") {
		t.Fatalf("CheckFDs with descriptors open = %v", err)
	}

	_ = f.Close()
	_ = pc.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := CheckFDs(ctx, base); err != nil {
		t.Fatal(err)
	}
}
