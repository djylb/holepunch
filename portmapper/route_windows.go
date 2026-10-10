//go:build windows

package portmapper

import (
	"errors"
	"net/netip"
	"syscall"
	"unsafe"
)

// errNoData is ERROR_NO_DATA, GetIpForwardTable's answer for an empty table.
const errNoData syscall.Errno = 232

// systemGateway reads the IPv4 default route with GetIpForwardTable. Package
// syscall registers iphlpapi.dll as a system DLL, so LoadDLL loads it from
// the system directory only; it is released after the call.
func systemGateway() (netip.Addr, error) {
	dll, err := syscall.LoadDLL("iphlpapi.dll")
	if err != nil {
		return netip.Addr{}, err
	}
	defer func() { _ = dll.Release() }()
	proc, err := dll.FindProc("GetIpForwardTable")
	if err != nil {
		return netip.Addr{}, err
	}
	size := uint32(16 << 10)
	for range 4 { // the table can grow between the size query and the call
		buf := make([]byte, size)
		r, _, _ := proc.Call(uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&size)), 0)
		switch errno := syscall.Errno(r); errno {
		case 0:
			return parseIPForwardTable(buf)
		case syscall.ERROR_INSUFFICIENT_BUFFER:
			continue
		case errNoData:
			return netip.Addr{}, errNoDefaultRoute
		default:
			return netip.Addr{}, errno
		}
	}
	return netip.Addr{}, errors.New("GetIpForwardTable: the table keeps growing")
}
