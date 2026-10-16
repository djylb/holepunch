package nattest

import (
	"context"
	"errors"
	"io"
	"net/netip"
	"syscall"
	"testing"
	"time"
)

func TestCrash(t *testing.T) {
	n := newNet(t)
	h := n.NAT(PortRestricted()).Host()
	srv := n.PublicHost()
	c1 := listen(t, h, 1000)
	listen(t, h, 2000)
	pa, pb := n.Pipe(PipeConfig{A: h, B: srv})
	done := make(chan error, 1)
	go func() { _, _, err := c1.ReadFromUDPAddrPort(make([]byte, 1)); done <- err }()
	time.Sleep(5 * time.Millisecond)
	h.Crash()
	if err := <-done; !isClosedErr(err) {
		t.Fatalf("blocked read: %v", err)
	}
	if h.OpenSockets() != 0 {
		t.Fatal("sockets survive Crash")
	}
	if _, err := pa.Write([]byte("x")); !isClosedErr(err) {
		t.Fatal(err)
	}
	_ = pb.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := pb.Read(make([]byte, 1)); err != io.EOF {
		t.Fatalf("peer of a crashed host: %v", err)
	}
	listen(t, h, 1000) // the host restarts
	if st := h.Stats(); st.SocketsOpened != 3 || st.SocketsClosed != 2 {
		t.Fatalf("%+v", st)
	}
}

func TestFailWrites(t *testing.T) {
	n := newNet(t)
	_, o := observer(t, n, 1)
	h := n.NAT(FullCone()).Host()
	bday, err := h.ListenPacket(context.Background(), "udp4", netip.AddrPort{}, "birthday")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = bday.Close() }()
	probe := listen(t, h, 2000)
	h.FailWrites("birthday", 2, syscall.ENOBUFS)
	for i := range 3 {
		_, err := bday.(udp).WriteToUDPAddrPort([]byte("x"), addrOf(o))
		if (i < 2) != errors.Is(err, syscall.ENOBUFS) {
			t.Fatalf("write %d: %v", i, err)
		}
	}
	send(t, probe, addrOf(o), "another purpose")
	h.FailWrites("", -1, nil) // every purpose, until cleared, EPERM by default
	for range 3 {
		if _, err := probe.WriteToUDPAddrPort([]byte("x"), addrOf(o)); !errors.Is(err, syscall.EPERM) {
			t.Fatal(err)
		}
	}
	h.FailWrites("", 0, nil)
	send(t, probe, addrOf(o), "cleared")
	if st := h.Stats(); st.InjectedWriteErrors != 5 || st.PacketsSent != 3 {
		t.Fatalf("%+v", st)
	}
}

func TestFailBinds(t *testing.T) {
	n := newNet(t)
	h := n.PublicHost()
	ctx := context.Background()
	h.FailBinds("sibling", 1)
	if _, err := h.ListenPacket(ctx, "udp", netip.AddrPort{}, "sibling"); !errors.Is(err, syscall.EADDRINUSE) {
		t.Fatal(err)
	}
	c, err := h.ListenPacket(ctx, "udp", netip.AddrPort{}, "sibling")
	if err != nil {
		t.Fatal("the rule must be used up", err)
	}
	_ = c.Close()
	h.FailBinds("", -1)
	if _, err := h.Listen("udp", netip.AddrPort{}); err == nil {
		t.Fatal("listen should fail")
	}
	h.FailBinds("", 0)
	c, err = h.Listen("udp", netip.AddrPort{})
	if err != nil {
		t.Fatal(err)
	}
	_ = c.Close()
	if st := h.Stats(); st.InjectedBindErrors != 2 || st.SocketsByPurpose[purposeListen] != 1 || st.SocketsByPurpose["sibling"] != 1 {
		t.Fatalf("%+v", st)
	}
}

func TestExpireAll(t *testing.T) {
	n := newNet(t)
	_, o := observer(t, n, 1)
	nat := n.NAT(SymmetricSeq(1))
	c := listen(t, nat.Host(), 4000)
	m := srcAt(t, c, o)
	nat.ExpireAll()
	send(t, o, m, "x")
	expectNone(t, c)
	if st := nat.Stats(); st.MappingsActive != 0 || st.MappingsExpired != 1 {
		t.Fatalf("%+v", st)
	}
	// The sequential cursor survives the reboot.
	if m2 := srcAt(t, c, o); m2.Port() != m.Port()+1 {
		t.Fatalf("after the reboot %v, want the port after %v", m2, m)
	}
}

func TestRebind(t *testing.T) {
	n := newNet(t)
	_, o := observer(t, n, 1)
	nat := n.NAT(FullCone())
	c := listen(t, nat.Host(), 4000)
	m := srcAt(t, c, o)
	old := ext(t, nat)
	nat.Rebind(nil)
	fresh := ext(t, nat)
	if fresh == old {
		t.Fatal("address unchanged")
	}
	send(t, o, m, "to the old address")
	expectNone(t, c)
	if st := n.Stats(); st.Dropped.NoRoute != 1 {
		t.Fatalf("the old address is still routed: %+v", st.Dropped)
	}
	if m2 := srcAt(t, c, o); m2.Addr() != fresh {
		t.Fatal(m2)
	}
	explicit := netip.MustParseAddr("198.51.100.250")
	nat.Rebind([]netip.Addr{explicit, {}})
	if m3 := srcAt(t, c, o); m3.Addr() != explicit {
		t.Fatal(m3)
	}
	if nat.Stats().MappingsExpired != 2 {
		t.Fatal("Rebind must flush the mappings")
	}
	nat.Rebind([]netip.Addr{explicit}) // rebinding onto its own address is allowed
}

func TestBlackhole(t *testing.T) {
	n, clk := fakeNet(t)
	_, o := observer(t, n, 1)
	nat := n.NAT(FullCone())
	c := listen(t, nat.Host(), 4000)
	m := srcAt(t, c, o)
	nat.Blackhole(5 * time.Second)
	send(t, c, addrOf(o), "out")
	send(t, o, m, "in")
	expectNone(t, o)
	expectNone(t, c)
	clk.Advance(5 * time.Second)
	send(t, o, m, "in")
	recvNow(t, c)
	nat.Blackhole(time.Hour)
	nat.Blackhole(0)
	send(t, o, m, "in")
	recvNow(t, c)
	if nat.Stats().Dropped.Blackhole != 2 {
		t.Fatal(nat.Stats().Dropped)
	}
}

// A packet lost upstream was mapped first: the APDM NAT allocates for it,
// and the next mapping takes the port after it; only the matched
// destination loses, and a nil match ends the loss.
func TestDropUpstream(t *testing.T) {
	n := newNet(t)
	_, o1 := observer(t, n, 1)
	_, o2 := observer(t, n, 2)
	nat := n.NAT(SymmetricSeq(1))
	c := listen(t, nat.Host(), 4000)
	first := srcAt(t, c, o1)
	lost := addrOf(o2)
	nat.DropUpstream(func(dst netip.AddrPort) bool { return dst == lost })
	send(t, c, lost, "lost")
	expectNone(t, o2)
	if len(nat.Mappings()) != 2 {
		t.Fatalf("mappings %+v: the lost packet was not mapped", nat.Mappings())
	}
	send(t, c, addrOf(o1), "kept")
	if msg, from := recvNow(t, o1); msg != "kept" || from != first {
		t.Fatalf("got %q from %v, want the first mapping %v", msg, from, first)
	}
	nat.DropUpstream(nil)
	send(t, c, lost, "again")
	if _, from := recvNow(t, o2); from.Port() != first.Port()+1 {
		t.Fatalf("second destination mapped at %v, want the port after %v", from, first)
	}
	if d := nat.Stats().Dropped.Loss; d != 1 {
		t.Fatalf("uplink loss %d, want 1", d)
	}
}

func TestMarkHandover(t *testing.T) {
	n := newNet(t)
	_, o := observer(t, n, 1)
	h := n.NAT(FullCone()).Host()
	lib := listen(t, h, 4000)
	app, err := h.MarkHandover(netip.AddrPortFrom(netip.Addr{}, 4000))
	if err != nil {
		t.Fatal(err)
	}
	// The application's own calls are not counted.
	au := app.(udp)
	if _, err := au.WriteToUDPAddrPort([]byte("app"), addrOf(o)); err != nil {
		t.Fatal(err)
	}
	_, mapped := recvNow(t, o)
	if _, err := app.WriteTo([]byte("app"), nil); !errors.Is(err, syscall.EINVAL) {
		t.Fatal("a nil address was accepted")
	}
	_ = app.SetDeadline(time.Now().Add(time.Second))
	_ = app.SetReadDeadline(time.Now().Add(time.Second))
	_ = app.SetWriteDeadline(time.Time{})
	_ = au.SetHopLimit(0)
	send(t, o, mapped, "y")
	b := make([]byte, 4)
	if k, _, err := app.ReadFrom(b); err != nil || string(b[:k]) != "y" {
		t.Fatal(k, err)
	}
	send(t, o, mapped, "z")
	if _, _, err := au.ReadFromUDPAddrPort(b); err != nil {
		t.Fatal(err)
	}
	bufs := app.(interface {
		SetReadBuffer(int) error
		SetWriteBuffer(int) error
	})
	if bufs.SetReadBuffer(1<<20) != nil || bufs.SetWriteBuffer(1<<20) != nil {
		t.Fatal("buffers")
	}
	if app.LocalAddr().String() != lib.LocalAddr().String() {
		t.Fatal("LocalAddr")
	}
	if h.Stats().WritesAfterHandover != 0 {
		t.Fatal("the application's calls were counted")
	}
	// The library touching the socket afterwards is counted, for every
	// method but LocalAddr.
	_, _ = lib.WriteToUDPAddrPort([]byte("lib"), addrOf(o))
	_ = lib.SetReadDeadline(time.Time{})
	_ = lib.SetHopLimit(4)
	_ = lib.LocalAddr()
	if got := h.Stats().WritesAfterHandover; got != 3 {
		t.Fatalf("WritesAfterHandover = %d", got)
	}
	s := h.Stats().Sockets
	if len(s) != 1 || !s[0].Handover || s[0].Purpose != "test" || s[0].HopLimit != 4 {
		t.Fatalf("%+v", s)
	}
	if err := app.Close(); err != nil {
		t.Fatal(err)
	}
	if bufs.SetReadBuffer(1) == nil || bufs.SetWriteBuffer(1) == nil {
		t.Fatal("a closed socket accepted buffer sizes")
	}
	if _, err := h.MarkHandover(netip.AddrPortFrom(netip.Addr{}, 9)); !errors.Is(err, syscall.ENOENT) {
		t.Fatalf("unknown socket: %v", err)
	}
}

func TestInboxFullAndReadBuffer(t *testing.T) {
	n := newNet(t)
	srv := n.PublicHost(netip.IPv4Unspecified())
	s := listenOn(t, srv, "udp4", netip.AddrPortFrom(srv.Addrs()[0], 1))
	c := listen(t, n.PublicHost(netip.IPv4Unspecified()), 2)
	for range inboxPackets + 5 {
		send(t, c, addrOf(s), "x")
	}
	if st := srv.Stats(); st.DroppedInboxFull != 5 || st.PacketsRecv != inboxPackets {
		t.Fatalf("%+v", st)
	}
	drain(s)
	_ = s.(interface{ SetReadBuffer(int) error }).SetReadBuffer(10)
	for range 5 {
		send(t, c, addrOf(s), "abcd")
	}
	if queued(s) != 2 {
		t.Fatalf("a read buffer of 10 bytes queued %d packets", queued(s))
	}
	if st := n.Stats(); st.DroppedInboxFull != 8 {
		t.Fatalf("%+v", st)
	}
}

// TestMarkHandoverPicksTheReceivingSocket: a specific address selects the
// socket that receives at it, never a wildcard of the other family on the
// same port; an unspecified one selects deterministically.
func TestMarkHandoverPicksTheReceivingSocket(t *testing.T) {
	n := newNet(t)
	lo4, hi4 := netip.MustParseAddr("198.51.100.20"), netip.MustParseAddr("198.51.100.21")
	h := n.PublicHost(hi4, lo4, netip.IPv6Unspecified())
	v6 := h.Addrs()[2]
	wild4 := listenOn(t, h, "udp4", netip.AddrPortFrom(netip.Addr{}, 5000))
	at6 := listenOn(t, h, "udp6", netip.AddrPortFrom(v6, 5000))
	byLow := listenOn(t, h, "udp4", netip.AddrPortFrom(lo4, 6000))
	listenOn(t, h, "udp4", netip.AddrPortFrom(hi4, 6000))
	for _, tc := range []struct {
		local netip.AddrPort
		want  udp
	}{
		{netip.AddrPortFrom(v6, 5000), at6},
		{netip.AddrPortFrom(lo4, 5000), wild4},
		{netip.AddrPortFrom(netip.IPv6Unspecified(), 5000), at6},
		{netip.AddrPortFrom(netip.Addr{}, 5000), wild4},
		{netip.AddrPortFrom(netip.Addr{}, 6000), byLow},
	} {
		for range 8 { // a map-order pick would differ between calls
			got, err := h.MarkHandover(tc.local)
			if err != nil {
				t.Fatal(err)
			}
			if got.(callerConn).c != tc.want.(*conn) {
				t.Fatalf("MarkHandover(%v) chose %v, want %v", tc.local, got.LocalAddr(), tc.want.LocalAddr())
			}
		}
	}
}
