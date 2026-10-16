package udpicmp

import (
	"errors"
	"net"
	"net/netip"
	"syscall"
	"testing"
	"time"
)

func TestClassifyWinsock(t *testing.T) {
	cases := []struct {
		err             syscall.Errno
		report, noRoute bool
	}{
		{syscall.WSAECONNRESET, true, false},
		{wsaENETRESET, true, false},
		{wsaEHOSTUNREACH, true, true},
		{wsaENETUNREACH, true, true},
		{wsaEHOSTDOWN, true, true},
		{syscall.WSAECONNABORTED, false, false},
		{syscall.WSAEACCES, false, false},
	}
	for _, tc := range cases {
		err := wrapped(tc.err)
		if got := IsReport(err); got != tc.report {
			t.Errorf("IsReport(%v) = %v", err, got)
		}
		if got := IsNoRoute(err); got != tc.noRoute {
			t.Errorf("IsNoRoute(%v) = %v", err, got)
		}
	}
}

// With the reports on, the read after a send to a closed loopback port
// fails with WSAECONNRESET; DisableReports turns that off on the same
// socket, which then reads on.
func TestReportsSwitch(t *testing.T) {
	c, err := net.ListenUDP("udp4", net.UDPAddrFromAddrPort(netip.MustParseAddrPort("127.0.0.1:0")))
	if err != nil {
		t.Skip("no IPv4 loopback:", err)
	}
	defer func() { _ = c.Close() }()
	closed := closedPort(t)
	if err := EnableReports(c); err != nil {
		t.Fatal(err)
	}
	if _, err := c.WriteToUDPAddrPort([]byte("x"), closed); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 64)
	_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
	_, _, err = c.ReadFromUDPAddrPort(buf)
	if !errors.Is(err, syscall.WSAECONNRESET) || !IsReport(err) {
		t.Fatalf("read with reports on: %v", err)
	}
	if err := DisableReports(c); err != nil {
		t.Fatal(err)
	}
	if _, err := c.WriteToUDPAddrPort([]byte("x"), closed); err != nil {
		t.Fatal(err)
	}
	_ = c.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
	var ne net.Error
	if _, _, err = c.ReadFromUDPAddrPort(buf); !errors.As(err, &ne) || !ne.Timeout() {
		t.Fatalf("read with reports off: %v, want a timeout", err)
	}
}

// closedPort returns a loopback port that nothing listens on.
func closedPort(t *testing.T) netip.AddrPort {
	t.Helper()
	c, err := net.ListenUDP("udp4", net.UDPAddrFromAddrPort(netip.MustParseAddrPort("127.0.0.1:0")))
	if err != nil {
		t.Fatal(err)
	}
	ap := c.LocalAddr().(*net.UDPAddr).AddrPort()
	_ = c.Close()
	return ap
}
