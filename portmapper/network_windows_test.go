package portmapper

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/djylb/holepunch/internal/life"
	"github.com/djylb/holepunch/internal/udpicmp"
)

// A request socket gets the Windows ICMP reports switched off, whatever the
// Network left on: a send to a closed port leaves the next read waiting
// instead of failing it.
func TestRequestSocketReportsOff(t *testing.T) {
	m := newTestMapper(t, Config{Network: &reportsOnNetwork{}}, testEnv{})
	c, err := m.openRequest(context.Background(), loopback)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	closed := netip.AddrPortFrom(loopback, closedUDPPort(t))
	if _, err := c.pc.WriteTo([]byte("x"), net.UDPAddrFromAddrPort(closed)); err != nil {
		t.Fatal(err)
	}
	_ = c.pc.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
	var ne net.Error
	if _, _, err := c.pc.ReadFrom(make([]byte, 64)); !errors.As(err, &ne) || !ne.Timeout() {
		t.Fatalf("read after a send to a closed port: %v, want a timeout", err)
	}
}

// A conn whose SyscallConn panics fails that one request, closed.
func TestRequestSocketSwitchPanics(t *testing.T) {
	n := &reportsOnNetwork{panicSyscall: true}
	m := newTestMapper(t, Config{Network: n}, testEnv{})
	_, err := m.openRequest(context.Background(), loopback)
	var pe *life.PanicError
	if !errors.As(err, &pe) {
		t.Fatalf("openRequest = %v, want a PanicError", err)
	}
	if n.closed.Load() != 1 {
		t.Fatalf("%d conns closed, want 1", n.closed.Load())
	}
}

// reportsOnNetwork opens loopback sockets with the Windows ICMP reports on,
// optionally behind a conn whose SyscallConn panics.
type reportsOnNetwork struct {
	panicSyscall bool
	closed       atomic.Int32
}

func (n *reportsOnNetwork) ListenPacket(_ context.Context, network string, laddr netip.AddrPort, _ string) (net.PacketConn, error) {
	c, err := net.ListenUDP(network, net.UDPAddrFromAddrPort(laddr))
	if err != nil {
		return nil, err
	}
	if err := udpicmp.EnableReports(c); err != nil {
		_ = c.Close()
		return nil, err
	}
	if n.panicSyscall {
		return &panicSyscallConn{UDPConn: c, closed: &n.closed}, nil
	}
	return c, nil
}

func (n *reportsOnNetwork) OutboundAddr(_ context.Context, _ string) (netip.Addr, error) {
	return loopback, nil
}

type panicSyscallConn struct {
	*net.UDPConn
	closed *atomic.Int32
}

func (c *panicSyscallConn) SyscallConn() (syscall.RawConn, error) { panic("SyscallConn exploded") }

func (c *panicSyscallConn) Close() error {
	c.closed.Add(1)
	return c.UDPConn.Close()
}
