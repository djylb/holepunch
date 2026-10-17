package udpsock

import (
	"errors"
	"net"
	"os"
	"syscall"
	"unsafe"
)

// Winsock error codes that package syscall does not name (winerror.h).
const (
	wsaENETUNREACH  syscall.Errno = 10051
	wsaENETRESET    syscall.Errno = 10052
	wsaEHOSTDOWN    syscall.Errno = 10064
	wsaEHOSTUNREACH syscall.Errno = 10065
)

// sioUDPNetReset is SIO_UDP_NETRESET (mstcpip.h, _WSAIOW(IOC_VENDOR)),
// the switch of the WSAENETRESET reports that ICMP "time exceeded" causes;
// package syscall names only its sibling SIO_UDP_CONNRESET.
const sioUDPNetReset = syscall.IOC_IN | syscall.IOC_VENDOR | 15

// DisableICMPReports switches off both kinds of ICMP report on c:
// SIO_UDP_CONNRESET (port unreachable, reported as WSAECONNRESET) and
// SIO_UDP_NETRESET (TTL expired, reported as WSAENETRESET). A conn that does
// not implement syscall.Conn is left alone.
//
// Package net does the same for every UDP socket it creates (Go issues 5834
// and 68614). Doing it here as well covers conns that expose their socket
// some other way and does not rest on that undocumented behaviour.
func DisableICMPReports(c net.PacketConn) error { return setReports(c, false) }

// EnableICMPReports switches both kinds of report back on: Windows' default for
// a socket that package net did not create. Tests use it to model such a
// socket.
func EnableICMPReports(c net.PacketConn) error { return setReports(c, true) }

func setReports(c net.PacketConn, on bool) error {
	sc, ok := c.(syscall.Conn)
	if !ok {
		return nil
	}
	rc, err := sc.SyscallConn()
	if err != nil {
		return err
	}
	var flag uint32 // a BOOL
	if on {
		flag = 1
	}
	var ioErr error
	if err := rc.Control(func(fd uintptr) {
		for _, code := range [...]uint32{syscall.SIO_UDP_CONNRESET, sioUDPNetReset} {
			in, ret := flag, uint32(0)
			if e := syscall.WSAIoctl(syscall.Handle(fd), code, (*byte)(unsafe.Pointer(&in)), uint32(unsafe.Sizeof(in)), nil, 0, &ret, nil, 0); e != nil {
				ioErr = errors.Join(ioErr, os.NewSyscallError("wsaioctl", e))
			}
		}
	}); err != nil {
		return err
	}
	return ioErr
}

// reportErrno reports whether e is a Winsock report, or one of the POSIX
// names that package syscall gives invented values on Windows and that
// simulators return.
func reportErrno(e syscall.Errno) bool {
	return errors.Is(e, syscall.WSAECONNRESET) || errors.Is(e, wsaENETRESET) ||
		errors.Is(e, syscall.ECONNREFUSED) || errors.Is(e, syscall.ECONNRESET)
}

func noRouteErrno(e syscall.Errno) bool {
	return errors.Is(e, wsaEHOSTUNREACH) || errors.Is(e, wsaENETUNREACH) || errors.Is(e, wsaEHOSTDOWN) ||
		errors.Is(e, syscall.EHOSTUNREACH) || errors.Is(e, syscall.ENETUNREACH) || errors.Is(e, syscall.EHOSTDOWN)
}
