package portmapper

import (
	"bytes"
	"net/netip"
	"testing"
)

// The parsers read datagrams and tables that come from the network or the
// operating system. None may panic, and what they accept must satisfy the
// checks the rest of the package relies on.

func FuzzPCPResponse(f *testing.F) {
	f.Add(pcpReply(pcpSuccess, testNonce, 1000, 54321, "198.51.100.25", 3600))
	f.Add(pcpReply(pcpNotAuthorized, testNonce, 1000, 0, "0.0.0.0", 0)[:pcpHeaderLen])
	f.Add([]byte{0, 0x81, 0, 1, 0, 0, 0, 0})
	f.Fuzz(func(t *testing.T, b []byte) {
		resp, ok, err := parsePCPMap(b, testNonce, 1000)
		if !ok {
			return
		}
		if err != nil || len(b) < pcpMapMsgLen || resp.code != pcpSuccess || !bytes.Equal(b[24:36], testNonce[:]) {
			t.Fatalf("accepted %x: %+v, %v", b, resp, err)
		}
	})
}

func FuzzNATPMPResponse(f *testing.F) {
	f.Add([]byte{0, 128, 0, 0, 0, 0, 0, 9, 203, 0, 113, 7})
	f.Add([]byte{0, 129, 0, 0, 0, 0, 0, 0, 3, 232, 19, 136, 0, 0, 14, 16})
	f.Add([]byte{2, 0x80, 0, 1})
	f.Fuzz(func(t *testing.T, b []byte) {
		if _, ok, err := parseNATPMPExternal(b); ok && (err != nil || len(b) < natpmpExtRespLen) {
			t.Fatalf("external answer %x accepted with %v", b, err)
		}
		if _, _, ok, err := parseNATPMPMap(b, 1000); ok && (err != nil || len(b) < natpmpMapRespLen) {
			t.Fatalf("map answer %x accepted with %v", b, err)
		}
	})
}

func FuzzSSDPResponse(f *testing.F) {
	f.Add([]byte("HTTP/1.1 200 OK\r\nST: urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\nLOCATION: http://127.0.0.1:1/x\r\n\r\n"))
	f.Add([]byte("HTTP/1.1 200 OK\r\nST: urn:schemas-upnp-org:device:InternetGatewayDevice:2\r\nLOCATION: http://[::ffff:127.0.0.1]:80/\r\n\r\n"))
	f.Add([]byte("NOTIFY * HTTP/1.1\r\n\r\n"))
	from := netip.MustParseAddr("127.0.0.1")
	f.Fuzz(func(t *testing.T, b []byte) {
		loc, ok := parseSSDPResponse(b, from)
		if !ok {
			return
		}
		host, err := netip.ParseAddr(loc.Hostname())
		if loc.Scheme != "http" || err != nil || host.Unmap() != from {
			t.Fatalf("accepted description URL %s from %s", loc, from)
		}
	})
}

func FuzzRouteTables(f *testing.F) {
	f.Add([]byte("Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\n" +
		"eth0\t00000000\t0101A8C0\t0003\t0\t0\t100\t00000000\t0\t0\t0\n"))
	f.Add(ipForwardTable(2, ipForwardRow{"0.0.0.0", "0.0.0.0", "192.168.0.1", 25}))
	f.Fuzz(func(t *testing.T, b []byte) {
		for name, parse := range map[string]func([]byte) (netip.Addr, error){
			"proc/net/route":     parseProcNetRoute,
			"MIB_IPFORWARDTABLE": parseIPForwardTable,
		} {
			if a, err := parse(b); err == nil && (!a.Is4() || a.IsUnspecified()) {
				t.Fatalf("%s: gateway %s from %x", name, a, b)
			}
		}
	})
}
