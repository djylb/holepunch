package portmapper

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"
)

// deadlineConn records the read deadlines set on a request socket and when
// it was closed. With ignoreDeadlines it accepts deadlines without applying
// them, like a connection whose reads cannot be interrupted that way.
type deadlineConn struct {
	*net.UDPConn
	ignoreDeadlines bool

	mu        sync.Mutex
	deadlines []deadlineCall
	closedAt  time.Time
}

type deadlineCall struct{ at, deadline time.Time }

func (c *deadlineConn) SetReadDeadline(d time.Time) error {
	c.mu.Lock()
	c.deadlines = append(c.deadlines, deadlineCall{time.Now(), d})
	c.mu.Unlock()
	if c.ignoreDeadlines {
		return nil
	}
	return c.UDPConn.SetReadDeadline(d)
}

func (c *deadlineConn) Close() error {
	c.mu.Lock()
	if c.closedAt.IsZero() {
		c.closedAt = time.Now()
	}
	c.mu.Unlock()
	return c.UDPConn.Close()
}

// deadlineNetwork hands out deadlineConns.
type deadlineNetwork struct {
	ignoreDeadlines bool
	mu              sync.Mutex
	conns           []*deadlineConn
}

func (n *deadlineNetwork) ListenPacket(_ context.Context, network string, laddr netip.AddrPort, _ string) (net.PacketConn, error) {
	u, err := net.ListenUDP(network, net.UDPAddrFromAddrPort(laddr))
	if err != nil {
		return nil, err
	}
	c := &deadlineConn{UDPConn: u, ignoreDeadlines: n.ignoreDeadlines}
	n.mu.Lock()
	n.conns = append(n.conns, c)
	n.mu.Unlock()
	return c, nil
}

func (n *deadlineNetwork) OutboundAddr(_ context.Context, _ string) (netip.Addr, error) {
	return loopback, nil
}

// TestRequestSocketClosedWhenContextEnds: a request socket is private, so
// the end of the request's context closes it instead of interrupting the
// read by moving its deadline from another goroutine. The only deadlines
// ever set are future retransmission times, set by the reading goroutine,
// and cancellation works even on a connection that ignores deadlines.
func TestRequestSocketClosedWhenContextEnds(t *testing.T) {
	for _, ignore := range []bool{false, true} {
		t.Run(fmt.Sprintf("ignoreDeadlines=%v", ignore), func(t *testing.T) {
			gw := newFakeGW(t)
			gw.set(func(f *fakeGW) { f.pcpMode = serveSilent })
			dn := &deadlineNetwork{ignoreDeadlines: ignore}
			m := newTestMapper(t, Config{Network: dn}, testEnv{gw: gw})

			ctx, cancel := context.WithCancel(context.Background())
			c, err := m.openRequest(ctx, loopback)
			if err != nil {
				t.Fatal(err)
			}
			stop := time.AfterFunc(100*time.Millisecond, cancel)
			defer stop.Stop()
			start := time.Now()
			out, err := c.exchange(ctx, netip.AddrPortFrom(loopback, gw.port), []byte{pcpVersion, pcpOpMap}, func([]byte) (bool, error) {
				return false, nil
			})
			returned := time.Now()
			c.Close()
			within(t, "exchange() cancelled at 100ms", returned.Sub(start), 250*time.Millisecond)
			if out != unanswered || !errors.Is(err, errNoResponse) || !errors.Is(err, context.Canceled) {
				t.Fatalf("exchange() = %v, %v; want unanswered, no response, cancelled", out, err)
			}

			dn.mu.Lock()
			defer dn.mu.Unlock()
			if len(dn.conns) != 1 {
				t.Fatalf("%d sockets opened, want 1", len(dn.conns))
			}
			dc := dn.conns[0]
			dc.mu.Lock()
			defer dc.mu.Unlock()
			if dc.closedAt.IsZero() || dc.closedAt.After(returned) {
				t.Fatalf("socket closed at %v, exchange returned at %v: the end of ctx must close it", dc.closedAt, returned)
			}
			if len(dc.deadlines) == 0 {
				t.Fatal("no read deadline set: retransmissions are not scheduled")
			}
			for _, d := range dc.deadlines {
				if !d.deadline.After(d.at) {
					t.Fatalf("read deadline %v set at %v is not in the future: a read was interrupted through its deadline", d.deadline, d.at)
				}
			}
		})
	}
}

func TestExchangeRetransmits(t *testing.T) {
	gw := newFakeGW(t)
	gw.set(func(f *fakeGW) { f.pcpMode = serveSilent })
	m := newTestMapper(t, Config{}, testEnv{gw: gw})
	ctx, cancel := context.WithTimeout(context.Background(), 900*time.Millisecond)
	defer cancel()
	c, err := m.openRequest(ctx, loopback)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_, err = c.exchange(ctx, netip.AddrPortFrom(loopback, gw.port), []byte{pcpVersion, pcpOpMap}, func([]byte) (bool, error) {
		return false, nil
	})
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("exchange() error = %v", err)
	}
	// Sent at 0, 250 ms and 750 ms; the next one would be at 1750 ms.
	if got := gw.counts().received; got != 3 {
		t.Fatalf("gateway received %d requests in 900 ms, want 3", got)
	}
}

func TestExchangeAcceptsOnlyTheServer(t *testing.T) {
	server := listenLoopback(t)
	spoofer := listenLoopback(t)
	m := newTestMapper(t, Config{}, testEnv{})
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	c, err := m.openRequest(ctx, loopback)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	errc := make(chan error, 1)
	go func() {
		buf := make([]byte, 64)
		_, client, err := server.ReadFromUDPAddrPort(buf)
		if err != nil {
			errc <- err
			return
		}
		// The spoofed answer arrives first and must be ignored.
		if _, err := spoofer.WriteToUDPAddrPort([]byte("spoofed"), client); err != nil {
			errc <- err
			return
		}
		time.Sleep(20 * time.Millisecond)
		_, err = server.WriteToUDPAddrPort([]byte("ignored"), client)
		if err == nil {
			_, err = server.WriteToUDPAddrPort([]byte("answer"), client)
		}
		errc <- err
	}()
	var got []string
	out, err := c.exchange(ctx, netip.AddrPortFrom(loopback, portOf(server)), []byte("request"), func(b []byte) (bool, error) {
		got = append(got, string(b))
		return string(b) == "answer", nil
	})
	if err != nil || out != answered {
		t.Fatalf("exchange() = %v, %v", out, err)
	}
	if err := <-errc; err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0] != "ignored" || got[1] != "answer" {
		t.Fatalf("accept saw %q, want only the server's datagrams", got)
	}

	// A negative answer ends the exchange as answered.
	refused := errors.New("refused")
	go func() {
		buf := make([]byte, 64)
		if _, client, err := server.ReadFromUDPAddrPort(buf); err == nil {
			_, _ = server.WriteToUDPAddrPort([]byte("no"), client)
		}
	}()
	out, err = c.exchange(ctx, netip.AddrPortFrom(loopback, portOf(server)), []byte("request"), func([]byte) (bool, error) {
		return false, refused
	})
	if out != answered || !errors.Is(err, refused) {
		t.Fatalf("exchange() = %v, %v; want answered, refused", out, err)
	}
}

func TestExchangeBeforeSending(t *testing.T) {
	m := newTestMapper(t, Config{}, testEnv{})
	ctx, cancel := context.WithCancel(context.Background())
	c, err := m.openRequest(ctx, loopback)
	if err != nil {
		t.Fatal(err)
	}
	cancel()
	out, err := c.exchange(ctx, netip.AddrPortFrom(loopback, 9), []byte("x"), func([]byte) (bool, error) { return true, nil })
	c.Close()
	if out != notSent || errors.Is(err, errNoResponse) || !errors.Is(err, context.Canceled) {
		t.Fatalf("exchange(cancelled) = %v, %v; want notSent, cancelled", out, err)
	}
}

func TestAddrPortOf(t *testing.T) {
	for _, tc := range []struct {
		in   net.Addr
		want netip.AddrPort
	}{
		{&net.UDPAddr{IP: net.ParseIP("::ffff:192.0.2.1"), Port: 5351}, netip.MustParseAddrPort("192.0.2.1:5351")},
		{textAddr("192.0.2.2:1900"), netip.MustParseAddrPort("192.0.2.2:1900")},
		{nil, netip.AddrPort{}},
		{(*net.UDPAddr)(nil), netip.AddrPort{}},
	} {
		if got := addrPortOf(tc.in); got != tc.want {
			t.Errorf("addrPortOf(%v) = %s, want %s", tc.in, got, tc.want)
		}
	}
}

func TestMultiError(t *testing.T) {
	a, b := errors.New("pcp: refused"), errors.New("upnp: no device")
	err := fmt.Errorf("%w: %w", ErrUnsupported, multiError{a, b})
	if got, want := err.Error(), "portmapper: port mapping unavailable: pcp: refused; upnp: no device"; got != want {
		t.Fatalf("Error() = %q, want %q", got, want)
	}
	if !errors.Is(err, a) || !errors.Is(err, b) || !errors.Is(err, ErrUnsupported) {
		t.Fatal("multiError does not unwrap to every error")
	}
}

// stubConn is a request socket whose calls fail as configured.
type stubConn struct {
	net.PacketConn // nil: other calls panic
	writeErr       error
	deadlineErr    error
	readErr        error
}

func (c *stubConn) WriteTo(b []byte, _ net.Addr) (int, error) { return len(b), c.writeErr }
func (c *stubConn) SetReadDeadline(time.Time) error           { return c.deadlineErr }
func (c *stubConn) ReadFrom([]byte) (int, net.Addr, error)    { return 0, nil, c.readErr }
func (c *stubConn) Close() error                              { return nil }

func TestExchangeSocketErrors(t *testing.T) {
	broken := errors.New("socket broken")
	for _, tc := range []struct {
		name string
		conn *stubConn
		want outcome
	}{
		{"write fails", &stubConn{writeErr: broken}, notSent},
		{"deadline fails", &stubConn{deadlineErr: broken}, unanswered},
		{"read fails", &stubConn{readErr: broken}, unanswered},
	} {
		c := &reqConn{pc: tc.conn, stop: func() bool { return true }}
		out, err := c.exchange(context.Background(), netip.MustParseAddrPort("127.0.0.1:9"), []byte("x"), func([]byte) (bool, error) {
			return true, nil
		})
		if out != tc.want || !errors.Is(err, broken) {
			t.Errorf("%s: exchange() = %v, %v; want %v, %v", tc.name, out, err, tc.want, broken)
		}
	}
}
