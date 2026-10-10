//go:build linux

package portmapper

import (
	"encoding/binary"
	"math"
	"net/netip"
	"syscall"
	"testing"
	"unsafe"
)

// referenceGateway reads the default gateway of the main routing table over
// rtnetlink, a source independent of /proc/net/route: among the IPv4 unicast
// routes to 0.0.0.0/0 through a gateway, the one with the lowest priority.
func referenceGateway(t *testing.T) (netip.Addr, string, bool) {
	rib, err := syscall.NetlinkRIB(syscall.RTM_GETROUTE, syscall.AF_INET)
	if err != nil {
		t.Logf("rtnetlink unavailable, comparison skipped: %v", err)
		return netip.Addr{}, "", false
	}
	msgs, err := syscall.ParseNetlinkMessage(rib)
	if err != nil {
		t.Fatalf("parse rtnetlink dump: %v", err)
	}
	var best netip.Addr
	bestPrio := uint32(math.MaxUint32)
	for i := range msgs {
		msg := &msgs[i]
		if msg.Header.Type != syscall.RTM_NEWROUTE || len(msg.Data) < syscall.SizeofRtMsg {
			continue
		}
		rtm := (*syscall.RtMsg)(unsafe.Pointer(&msg.Data[0]))
		if rtm.Family != syscall.AF_INET || rtm.Dst_len != 0 || rtm.Table != syscall.RT_TABLE_MAIN || rtm.Type != syscall.RTN_UNICAST {
			continue
		}
		attrs, err := syscall.ParseNetlinkRouteAttr(msg)
		if err != nil {
			t.Fatalf("parse route attributes: %v", err)
		}
		var gw netip.Addr
		var prio uint32
		for _, a := range attrs {
			switch a.Attr.Type {
			case syscall.RTA_GATEWAY:
				if len(a.Value) == 4 {
					gw = netip.AddrFrom4([4]byte(a.Value))
				}
			case syscall.RTA_PRIORITY:
				if len(a.Value) == 4 {
					prio = binary.NativeEndian.Uint32(a.Value)
				}
			}
		}
		if gw.IsValid() && prio < bestPrio {
			best, bestPrio = gw, prio
		}
	}
	if !best.IsValid() {
		t.Log("rtnetlink lists no IPv4 default gateway, comparison skipped")
		return netip.Addr{}, "", false
	}
	return best, "rtnetlink", true
}
