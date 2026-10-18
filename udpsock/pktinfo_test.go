package udpsock

import (
	"errors"
	"net"
	"net/netip"
	"testing"
	"time"
)

// A wildcard socket with EnableDstAddr learns each datagram's destination
// and answers from it: a client that sent to a second loopback address
// (127.0.0.2, Linux) hears the reply from that address, not from the one
// the system would route by.
func TestDstAddr(t *testing.T) {
	cases := []struct {
		network        string
		wildcard, from string
		to             []string
	}{
		{"udp4", "0.0.0.0:0", "127.0.0.1:0", []string{"127.0.0.1", "127.0.0.2"}},
		{"udp6", "[::]:0", "[::1]:0", []string{"::1"}},
	}
	for _, c := range cases {
		t.Run(c.network, func(t *testing.T) {
			srv, err := net.ListenUDP(c.network, net.UDPAddrFromAddrPort(netip.MustParseAddrPort(c.wildcard)))
			if err != nil {
				t.Skip(err)
			}
			defer func() { _ = srv.Close() }()
			if err := EnableDstAddr(srv); errors.Is(err, errors.ErrUnsupported) {
				t.Skip(err)
			} else if err != nil {
				t.Fatal(err)
			}
			cli, err := net.ListenUDP(c.network, net.UDPAddrFromAddrPort(netip.MustParseAddrPort(c.from)))
			if err != nil {
				t.Skip(err)
			}
			defer func() { _ = cli.Close() }()
			port := srv.LocalAddr().(*net.UDPAddr).AddrPort().Port()
			for _, to := range c.to {
				dst := netip.AddrPortFrom(netip.MustParseAddr(to), port)
				if _, err := cli.WriteToUDPAddrPort([]byte("ping"), dst); err != nil {
					t.Logf("%v: %v (skipped)", dst, err)
					continue
				}
				wait := 2 * time.Second
				if to != c.to[0] {
					wait = 300 * time.Millisecond // may not exist here
				}
				_ = srv.SetReadDeadline(time.Now().Add(wait))
				buf, oob := make([]byte, 64), make([]byte, ControlSize)
				n, oobn, _, from, err := srv.ReadMsgUDPAddrPort(buf, oob)
				if err != nil {
					if to != c.to[0] {
						t.Logf("%v: %v (no such loopback address here)", dst, err)
						continue
					}
					t.Fatal(err)
				}
				got, ok := DstAddr(oob[:oobn])
				if !ok || got != dst.Addr() || string(buf[:n]) != "ping" {
					t.Fatalf("destination %v %v, want %v", got, ok, dst.Addr())
				}
				if _, _, err := srv.WriteMsgUDPAddrPort([]byte("pong"), AppendSrcAddr(nil, got), from); err != nil {
					if to != c.to[0] {
						// 127.0.0.2 receives but is no interface address:
						// some systems (Windows) refuse it as a source.
						t.Logf("%v as a source: %v (refused here)", got, err)
						continue
					}
					t.Fatal(err)
				}
				_ = cli.SetReadDeadline(time.Now().Add(2 * time.Second))
				n, src, err := cli.ReadFromUDPAddrPort(buf)
				if err != nil {
					t.Fatal(err)
				}
				if src.Addr().Unmap() != dst.Addr() || src.Port() != port || string(buf[:n]) != "pong" {
					t.Fatalf("reply from %v, want %v", src, dst)
				}
			}
		})
	}
}

// The control messages round-trip through the parser, and junk parses to
// nothing.
func TestControlMessages(t *testing.T) {
	for _, a := range []string{"192.0.2.7", "2001:db8::7"} {
		src := netip.MustParseAddr(a)
		oob := AppendSrcAddr(nil, src)
		if len(oob) == 0 {
			continue // no source message on this platform
		}
		if len(oob) > ControlSize {
			t.Fatalf("%v: %d bytes > ControlSize", src, len(oob))
		}
		// The send form of the IPv4 message is not the receive form on
		// every platform; IPv6's is.
		if got, ok := DstAddr(oob); src.Is6() && (!ok || got != src) {
			t.Fatalf("%v parsed as %v %v", src, got, ok)
		}
		// Control data at any offset of a slice: no alignment is assumed.
		odd := AppendSrcAddr([]byte{0xAA}, src)[1:]
		if got, ok := DstAddr(odd); src.Is6() && (!ok || got != src) {
			t.Fatalf("%v at an odd offset parsed as %v %v", src, got, ok)
		}
	}
	for _, junk := range [][]byte{nil, {1}, make([]byte, ControlSize), {0xff, 0xff, 0xff, 0xff, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}} {
		if a, ok := DstAddr(junk); ok {
			t.Fatalf("junk % x parsed as %v", junk, a)
		}
	}
	if got := AppendSrcAddr([]byte{1}, netip.Addr{}); len(got) != 1 {
		t.Fatal("an invalid source appended a message")
	}
}
