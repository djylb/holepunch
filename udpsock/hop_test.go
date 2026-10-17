package udpsock

import (
	"errors"
	"net"
	"net/netip"
	"testing"
)

// HopLimit and SetHopLimit work on both families, and a value set reads
// back; a conn without a socket and a value out of range are refused.
func TestHopLimit(t *testing.T) {
	for _, tc := range []struct{ network, addr string }{{"udp4", "127.0.0.1:0"}, {"udp6", "[::1]:0"}} {
		t.Run(tc.network, func(t *testing.T) {
			c, err := net.ListenUDP(tc.network, net.UDPAddrFromAddrPort(netip.MustParseAddrPort(tc.addr)))
			if err != nil {
				t.Skip("no loopback:", err)
			}
			defer func() { _ = c.Close() }()
			orig, err := HopLimit(c)
			if errors.Is(err, errors.ErrUnsupported) {
				t.Skip(err)
			}
			if err != nil || orig < 0 {
				t.Fatalf("HopLimit %d, %v", orig, err)
			}
			if err := SetHopLimit(c, 3); err != nil {
				t.Fatal(err)
			}
			if v, err := HopLimit(c); err != nil || v != 3 {
				t.Fatalf("after SetHopLimit(3): %d, %v", v, err)
			}
			if err := SetHopLimit(c, orig); err != nil {
				t.Fatal(err)
			}
			for _, bad := range []int{-1, 256} {
				if err := SetHopLimit(c, bad); err == nil {
					t.Errorf("SetHopLimit(%d) accepted", bad)
				}
			}
			if _, err := HopLimit(plainConn{c}); !errors.Is(err, errors.ErrUnsupported) {
				t.Errorf("a conn without a socket: %v", err)
			}
		})
	}
}
