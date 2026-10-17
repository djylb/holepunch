package hostaddr

import (
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"syscall"
)

// interfacesFallback lists the interfaces and addresses from a netlink
// RTM_GETADDR dump, for systems that refuse net.Interfaces: Android 11 and
// later deny ordinary apps both RTM_GETLINK, which package net needs, and
// binding a netlink socket, which syscall.NetlinkRIB does; a sandboxed
// container may deny the first. An address dump needs neither. It knows no
// link flags: an interface with an address is taken to be up, one with a
// loopback address to be loopback, and one whose address has a peer
// (IFA_ADDRESS ≠ IFA_LOCAL) to be point-to-point; names come from the IPv4
// labels.
//
//holepunch:netimpl
func interfacesFallback() ([]net.Interface, [][]netip.Prefix, error) {
	msgs, err := dumpAddrs()
	if err != nil {
		return nil, nil, err
	}
	var ifaces []net.Interface
	var addrs [][]netip.Prefix
	at := map[int]int{} // interface index -> position
	for _, m := range msgs {
		if m.Header.Type != syscall.RTM_NEWADDR || len(m.Data) < syscall.SizeofIfAddrmsg {
			continue
		}
		ifa := m.Data[:syscall.SizeofIfAddrmsg]
		family, bits, index := ifa[0], int(ifa[1]), int(binary.NativeEndian.Uint32(ifa[4:8]))
		attrs, err := syscall.ParseNetlinkRouteAttr(&m)
		if err != nil {
			continue
		}
		var local, peer netip.Addr
		var label string
		for _, a := range attrs {
			switch a.Attr.Type {
			case syscall.IFA_LOCAL:
				local, _ = netip.AddrFromSlice(a.Value)
			case syscall.IFA_ADDRESS:
				peer, _ = netip.AddrFromSlice(a.Value)
			case syscall.IFA_LABEL:
				label = string(trimNUL(a.Value))
			}
		}
		addr := local
		if !addr.IsValid() {
			addr = peer // IPv6 and broadcast links report only IFA_ADDRESS
		}
		if !addr.IsValid() || (family != syscall.AF_INET && family != syscall.AF_INET6) {
			continue
		}
		i, ok := at[index]
		if !ok {
			i = len(ifaces)
			at[index] = i
			ifaces = append(ifaces, net.Interface{Index: index, Flags: net.FlagUp})
			addrs = append(addrs, nil)
		}
		ifc := &ifaces[i]
		if ifc.Name == "" && label != "" {
			ifc.Name = label
		}
		if addr.IsLoopback() {
			ifc.Flags |= net.FlagLoopback
		}
		if local.IsValid() && peer.IsValid() && local != peer {
			ifc.Flags |= net.FlagPointToPoint
		}
		addr = addr.Unmap()
		addrs[i] = append(addrs[i], netip.PrefixFrom(addr, min(bits, addr.BitLen())))
	}
	if len(ifaces) == 0 {
		return nil, nil, errors.New("hostaddr: netlink: no addresses")
	}
	return ifaces, addrs, nil
}

// dumpAddrs sends one RTM_GETADDR dump request on an unbound netlink socket
// and reads the reply up to NLMSG_DONE.
func dumpAddrs() ([]syscall.NetlinkMessage, error) {
	s, err := syscall.Socket(syscall.AF_NETLINK, syscall.SOCK_RAW|syscall.SOCK_CLOEXEC, syscall.NETLINK_ROUTE)
	if err != nil {
		return nil, err
	}
	defer func() { _ = syscall.Close(s) }()
	tv := syscall.NsecToTimeval(2e9) // the kernel always ends a dump; this bounds a stuck one
	_ = syscall.SetsockoptTimeval(s, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &tv)
	const seq = 1
	req := make([]byte, syscall.NLMSG_HDRLEN+syscall.SizeofRtGenmsg)
	binary.NativeEndian.PutUint32(req[0:], uint32(len(req)))
	binary.NativeEndian.PutUint16(req[4:], syscall.RTM_GETADDR)
	binary.NativeEndian.PutUint16(req[6:], syscall.NLM_F_REQUEST|syscall.NLM_F_DUMP)
	binary.NativeEndian.PutUint32(req[8:], seq)
	req[syscall.NLMSG_HDRLEN] = syscall.AF_UNSPEC
	if err := syscall.Sendto(s, req, 0, &syscall.SockaddrNetlink{Family: syscall.AF_NETLINK}); err != nil {
		return nil, err
	}
	var out []syscall.NetlinkMessage
	buf := make([]byte, 1<<16)
	for range 1 << 12 { // a host with thousands of addresses still ends
		n, _, err := syscall.Recvfrom(s, buf, 0)
		if err != nil {
			return nil, err
		}
		msgs, err := syscall.ParseNetlinkMessage(buf[:n])
		if err != nil {
			return nil, err
		}
		for _, m := range msgs {
			if m.Header.Seq != seq {
				continue
			}
			switch m.Header.Type {
			case syscall.NLMSG_DONE:
				return out, nil
			case syscall.NLMSG_ERROR:
				return nil, errors.New("hostaddr: netlink: dump refused")
			}
			m.Data = append([]byte(nil), m.Data...) // buf is reused
			out = append(out, m)
		}
	}
	return nil, errors.New("hostaddr: netlink: dump did not end")
}

func trimNUL(b []byte) []byte {
	for i, c := range b {
		if c == 0 {
			return b[:i]
		}
	}
	return b
}
