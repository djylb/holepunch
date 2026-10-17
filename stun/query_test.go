package stun

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"testing"
	"time"
)

// reflector answers Binding Requests on a loopback socket, after dropping
// the first drop of them; with drop 0 it is Serve.
func reflector(t *testing.T, drop int) netip.AddrPort {
	t.Helper()
	c, err := net.ListenUDP("udp4", net.UDPAddrFromAddrPort(netip.MustParseAddrPort("127.0.0.1:0")))
	if err != nil {
		t.Skip("no IPv4 loopback:", err)
	}
	t.Cleanup(func() { _ = c.Close() })
	if drop == 0 {
		go func() { _ = Serve(c) }()
		return c.LocalAddr().(*net.UDPAddr).AddrPort()
	}
	go func() {
		buf := make([]byte, 1500)
		for {
			n, from, err := c.ReadFromUDPAddrPort(buf)
			if err != nil {
				return
			}
			id, ok := ParseBindingRequest(buf[:n])
			if !ok {
				continue
			}
			if drop > 0 {
				drop--
				continue
			}
			_, _ = c.WriteToUDPAddrPort(AppendBindingResponse(nil, id, from), from)
		}
	}()
	return c.LocalAddr().(*net.UDPAddr).AddrPort()
}

func client(t *testing.T) *net.UDPConn {
	t.Helper()
	c, err := net.ListenUDP("udp4", net.UDPAddrFromAddrPort(netip.MustParseAddrPort("127.0.0.1:0")))
	if err != nil {
		t.Skip("no IPv4 loopback:", err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

// Query returns the socket's address as the server saw it, after a lost
// request too, and leaves the read deadline cleared.
func TestQuery(t *testing.T) {
	for _, drop := range []int{0, 1} {
		srv := reflector(t, drop)
		c := client(t)
		got, err := Query(context.Background(), c, srv)
		if err != nil {
			t.Fatalf("drop %d: %v", drop, err)
		}
		if want := c.LocalAddr().(*net.UDPAddr).AddrPort(); got != want {
			t.Fatalf("drop %d: mapped %v, want %v", drop, got, want)
		}
		if err := c.SetReadDeadline(time.Now().Add(20 * time.Millisecond)); err != nil {
			t.Fatal(err)
		}
	}
}

// A Query nobody answers ends with ctx, promptly, with ctx's cause.
func TestQueryContext(t *testing.T) {
	silent := client(t) // a socket that never answers
	c := client(t)
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err := Query(ctx, c, silent.LocalAddr().(*net.UDPAddr).AddrPort())
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err %v", err)
	}
	if d := time.Since(start); d > 2*time.Second {
		t.Fatalf("returned after %v", d)
	}

	cctx, cancelCause := context.WithCancelCause(context.Background())
	stop := errors.New("stop")
	time.AfterFunc(50*time.Millisecond, func() { cancelCause(stop) })
	if _, err := Query(cctx, c, silent.LocalAddr().(*net.UDPAddr).AddrPort()); !errors.Is(err, stop) {
		t.Fatalf("canceled: %v", err)
	}
	if _, err := Query(context.Background(), c, netip.AddrPort{}); err == nil {
		t.Fatal("invalid server accepted")
	}
}

// A response from another address, or to another transaction, is ignored.
func TestQueryIgnoresStrangers(t *testing.T) {
	srv := reflector(t, 0)
	c := client(t)
	stranger := client(t)
	go func() {
		to := c.LocalAddr().(*net.UDPAddr)
		fake := AppendBindingResponse(nil, NewTransactionID(), netip.MustParseAddrPort("192.0.2.1:9"))
		for range 5 {
			_, _ = stranger.WriteTo(fake, to)
		}
	}()
	got, err := Query(context.Background(), c, srv)
	if err != nil || got != c.LocalAddr().(*net.UDPAddr).AddrPort() {
		t.Fatalf("%v %v", got, err)
	}
}

func TestBindingRoundTrip(t *testing.T) {
	id := NewTransactionID()
	req := AppendBindingRequest(nil, id)
	if got, ok := ParseBindingRequest(req); !ok || got != id || !IsMessage(req) {
		t.Fatalf("request % x", req)
	}
	for _, ap := range []string{"203.0.113.5:40000", "[2001:db8::7]:5000", "[::ffff:192.0.2.9]:7"} {
		want := netip.MustParseAddrPort(ap)
		resp := AppendBindingResponse([]byte{0xAA}, id, want)[1:]
		if !IsMessage(resp) {
			t.Fatalf("%s: response % x", ap, resp)
		}
		got, mapped, ok := ParseBindingResponse(resp)
		want = netip.AddrPortFrom(want.Addr().Unmap(), want.Port())
		if !ok || got != id || mapped != want {
			t.Fatalf("%s: %v %v %v", ap, got, mapped, ok)
		}
		if _, ok := ParseBindingRequest(resp); ok {
			t.Fatalf("%s: a response parsed as a request", ap)
		}
	}
	if IsMessage(append(req, 0)) || IsMessage(req[:19]) {
		t.Fatal("IsMessage accepts a wrong length")
	}
}
