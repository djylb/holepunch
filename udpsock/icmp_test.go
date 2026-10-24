package udpsock

import (
	"errors"
	"net"
	"net/netip"
	"os"
	"syscall"
	"testing"

	"github.com/djylb/holepunch/internal/goroutines"
)

func TestMain(m *testing.M) { goroutines.VerifyTestMain(m) }

// wrapped is err as package net returns it from a socket call.
func wrapped(err error) error {
	return &net.OpError{Op: "read", Net: "udp4", Err: os.NewSyscallError("recvfrom", err)}
}

// The POSIX names classify the same on every platform: package syscall
// gives them invented values on Windows, and simulators return them.
func TestClassifyPOSIX(t *testing.T) {
	cases := []struct {
		err             error
		report, noRoute bool
	}{
		{wrapped(syscall.ECONNREFUSED), true, false},
		{wrapped(syscall.ECONNRESET), true, false},
		{wrapped(syscall.EHOSTUNREACH), true, true},
		{wrapped(syscall.ENETUNREACH), true, true},
		{syscall.ENETUNREACH, true, true},
		{wrapped(syscall.EINVAL), false, false},
		{errors.New("other"), false, false},
		{net.ErrClosed, false, false},
		{nil, false, false},
	}
	for _, tc := range cases {
		if got := IsICMPReport(tc.err); got != tc.report {
			t.Errorf("IsICMPReport(%v) = %v", tc.err, got)
		}
		if got := IsNoRoute(tc.err); got != tc.noRoute {
			t.Errorf("IsNoRoute(%v) = %v", tc.err, got)
		}
	}
}

// DisableICMPReports accepts any conn: a real socket, and one without
// syscall.Conn, which it leaves alone.
func TestDisableReports(t *testing.T) {
	c, err := net.ListenUDP("udp4", net.UDPAddrFromAddrPort(netip.MustParseAddrPort("127.0.0.1:0")))
	if err != nil {
		t.Skip("no IPv4 loopback:", err)
	}
	defer func() { _ = c.Close() }()
	if err := DisableICMPReports(c); err != nil {
		t.Fatal(err)
	}
	if err := DisableICMPReports(plainConn{c}); err != nil {
		t.Fatal(err)
	}
}

// plainConn hides the socket behind net.PacketConn.
type plainConn struct{ net.PacketConn }
