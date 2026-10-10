//go:build linux || darwin

package portmapper

import (
	"context"
	"encoding/binary"
	"net/netip"
	"runtime"
	"syscall"
	"testing"
	"time"

	"github.com/djylb/holepunch/protocol"
)

// TestMappedSocketKeepsHopLimit maps a *net.UDPConn and then lowers its TTL
// the way the client runtime does for low-TTL sends (through
// syscall.Conn), reading the TTL of the received datagrams with IP_RECVTTL.
// Map neither wraps nor replaces the socket, so the setting reaches the wire
// while the mapping is live, and release leaves the socket open.
func TestMappedSocketKeepsHopLimit(t *testing.T) {
	gw := newFakeGW(t)
	m := newTestMapper(t, Config{}, testEnv{gw: gw})

	rx := listenLoopback(t)
	rrc, err := rx.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var serr error
	if err := rrc.Control(func(fd uintptr) {
		serr = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IP, syscall.IP_RECVTTL, 1)
	}); err != nil || serr != nil {
		t.Skipf("IP_RECVTTL unavailable: %v %v", err, serr)
	}
	cmsgType := int32(syscall.IP_TTL)
	if runtime.GOOS == "darwin" {
		cmsgType = syscall.IP_RECVTTL
	}
	recvTTL := func() int {
		t.Helper()
		_ = rx.SetReadDeadline(time.Now().Add(2 * time.Second))
		buf, oob := make([]byte, 64), make([]byte, 256)
		_, oobn, _, _, err := rx.ReadMsgUDP(buf, oob)
		if err != nil {
			t.Fatal(err)
		}
		msgs, err := syscall.ParseSocketControlMessage(oob[:oobn])
		if err != nil {
			t.Fatal(err)
		}
		for _, msg := range msgs {
			if msg.Header.Level == syscall.IPPROTO_IP && msg.Header.Type == cmsgType {
				if len(msg.Data) >= 4 {
					return int(binary.NativeEndian.Uint32(msg.Data))
				}
				return int(msg.Data[0])
			}
		}
		t.Fatal("no TTL control message")
		return 0
	}

	pc := listenLoopback(t)
	_, release, err := m.Map(context.Background(), pc, protocol.PortMappingPolicy{})
	if err != nil {
		t.Fatal(err)
	}
	dst := rx.LocalAddr().(interface{ AddrPort() netip.AddrPort }).AddrPort()
	send := func() {
		t.Helper()
		if _, err := pc.WriteToUDPAddrPort([]byte("ttl"), dst); err != nil {
			t.Fatal(err)
		}
	}
	setTTL := func(v int) {
		t.Helper()
		rc, err := pc.SyscallConn() // the capability the runtime's HopLimiter uses
		if err != nil {
			t.Fatal(err)
		}
		var serr error
		if err := rc.Control(func(fd uintptr) {
			serr = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IP, syscall.IP_TTL, v)
		}); err != nil || serr != nil {
			t.Fatalf("set IP_TTL: %v %v", err, serr)
		}
	}

	send()
	orig := recvTTL()
	setTTL(3)
	send()
	if got := recvTTL(); got != 3 {
		t.Fatalf("received TTL %d from the mapped socket, want 3", got)
	}
	if err := release(); err != nil {
		t.Fatal(err)
	}
	setTTL(orig)
	send() // release did not close the socket
	if got := recvTTL(); got != orig {
		t.Fatalf("received TTL %d after restore, want %d", got, orig)
	}
}
