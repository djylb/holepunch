package portmapper

import (
	"context"
	"net/netip"
	"testing"

	"github.com/djylb/holepunch/protocol"
)

// BenchmarkMapRelease measures a whole mapping lifetime against the loopback
// fake: gateway cache hit, PCP create in parallel with the NAT-PMP probe,
// lease start, release (renewal stop and delete).
func BenchmarkMapRelease(b *testing.B) {
	gw := newFakeGW(b)
	m := newTestMapper(b, Config{}, testEnv{gw: gw})
	pc := listenLoopback(b)
	p := policy(0, protocol.PortMapPCP, protocol.PortMapNATPMP)
	b.ReportAllocs()
	for b.Loop() {
		_, release, err := m.Map(context.Background(), pc, p)
		if err != nil {
			b.Fatal(err)
		}
		if err := release(); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkPCPCodec(b *testing.B) {
	client := netip.MustParseAddr("192.168.1.10")
	resp := pcpReply(pcpSuccess, testNonce, 1000, 54321, "198.51.100.25", 3600)
	b.ReportAllocs()
	for b.Loop() {
		_ = buildPCPMap(client, testNonce, 1000, netip.AddrPort{}, 3600)
		if _, ok, err := parsePCPMap(resp, testNonce, 1000); !ok || err != nil {
			b.Fatal(ok, err)
		}
	}
}

func BenchmarkParseProcNetRoute(b *testing.B) {
	table := []byte("Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\n" +
		"eth0\t0001A8C0\t00000000\t0001\t0\t0\t100\t00FFFFFF\t0\t0\t0\n" +
		"eth0\t00000000\t" + procRouteHex("192.168.1.1") + "\t0003\t0\t0\t100\t00000000\t0\t0\t0\n")
	b.ReportAllocs()
	for b.Loop() {
		if _, err := parseProcNetRoute(table); err != nil {
			b.Fatal(err)
		}
	}
}
