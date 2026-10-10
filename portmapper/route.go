package portmapper

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"math"
	"net/netip"
	"strconv"
	"strings"
)

// The system default gateway lookup is implemented per platform in
// route_*.go as systemGateway. The table parsers live here, free of build
// constraints, so that every platform's parser is tested everywhere.

// parseProcNetRoute returns the gateway of the IPv4 default route with the
// lowest metric from the contents of Linux /proc/net/route:
//
//	Iface	Destination	Gateway 	Flags	RefCnt	Use	Metric	Mask		MTU	Window	IRTT
//	eth0	00000000	0101A8C0	0003	0	0	100	00000000	0	0	0
//
// Addresses are network-order words printed as native integers, so they are
// decoded with the host's byte order.
func parseProcNetRoute(b []byte) (netip.Addr, error) {
	const (
		rtfUp      = 0x1
		rtfGateway = 0x2
	)
	sc := bufio.NewScanner(bytes.NewReader(b))
	if !sc.Scan() { // header
		return netip.Addr{}, errNoDefaultRoute
	}
	var best netip.Addr
	bestMetric := uint64(math.MaxUint64)
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) < 8 {
			continue
		}
		dst, err1 := strconv.ParseUint(f[1], 16, 32)
		gw, err2 := strconv.ParseUint(f[2], 16, 32)
		flags, err3 := strconv.ParseUint(f[3], 16, 32)
		metric, err4 := strconv.ParseUint(f[6], 10, 32)
		mask, err5 := strconv.ParseUint(f[7], 16, 32)
		if err1 != nil || err2 != nil || err3 != nil || err4 != nil || err5 != nil {
			continue
		}
		if dst != 0 || mask != 0 || gw == 0 || flags&(rtfUp|rtfGateway) != rtfUp|rtfGateway || metric >= bestMetric {
			continue
		}
		var ip [4]byte
		binary.NativeEndian.PutUint32(ip[:], uint32(gw))
		best, bestMetric = netip.AddrFrom4(ip), metric
	}
	if !best.IsValid() {
		return netip.Addr{}, errNoDefaultRoute
	}
	return best, nil
}

// MIB_IPFORWARDTABLE layout (Windows GetIpForwardTable): a DWORD row count
// followed by MIB_IPFORWARDROW rows of 14 DWORDs. Addresses are in network
// byte order; the other DWORDs are little-endian on every Windows
// architecture.
const (
	ipForwardRowLen    = 56
	ipForwardDestOff   = 0
	ipForwardMaskOff   = 4
	ipForwardNextOff   = 12
	ipForwardMetricOff = 36
)

// parseIPForwardTable returns the next hop of the IPv4 default route with the
// lowest metric from a MIB_IPFORWARDTABLE.
func parseIPForwardTable(b []byte) (netip.Addr, error) {
	if len(b) < 4 {
		return netip.Addr{}, errNoDefaultRoute
	}
	rows := b[4:]
	n := min(int(binary.LittleEndian.Uint32(b)), len(rows)/ipForwardRowLen)
	var best netip.Addr
	bestMetric := uint32(math.MaxUint32)
	for i := range n {
		r := rows[i*ipForwardRowLen : (i+1)*ipForwardRowLen]
		dst := [4]byte(r[ipForwardDestOff:])
		mask := [4]byte(r[ipForwardMaskOff:])
		next := [4]byte(r[ipForwardNextOff:])
		metric := binary.LittleEndian.Uint32(r[ipForwardMetricOff:])
		if dst != [4]byte{} || mask != [4]byte{} || next == [4]byte{} || metric >= bestMetric {
			continue
		}
		best, bestMetric = netip.AddrFrom4(next), metric
	}
	if !best.IsValid() {
		return netip.Addr{}, errNoDefaultRoute
	}
	return best, nil
}
