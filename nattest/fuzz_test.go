package nattest

import (
	"net/netip"
	"slices"
	"testing"
	"time"

	"go.uber.org/goleak"

	"github.com/djylb/holepunch/clock"
)

// FuzzNATSim drives random outbound, inbound, time and reboot sequences
// through a randomly configured NAT and checks its invariants:
// the active mappings never exceed MaxMappings, filtering rejects exactly
// the packets that violate the configured rule (judged against the exported
// mapping state), and nothing keeps running after Close.
func FuzzNATSim(f *testing.F) {
	f.Add([]byte{0, 2, 0, 3, 1, 10, 20, 30, 40, 50, 60, 70, 80, 90, 100})
	f.Add([]byte{2, 2, 1, 1, 0, 1, 2, 3, 129, 130, 131, 200, 201, 4, 5, 6})
	f.Add([]byte{1, 1, 3, 2, 2, 7, 7, 7, 135, 135, 250, 7, 135, 64, 64, 199})
	f.Add([]byte{0, 0, 4, 0, 3, 255, 254, 253, 1, 2, 3, 128, 129, 130, 192, 193})
	f.Add([]byte{1, 0, 2, 1, 133, 0, 64, 65, 1, 66, 2, 67, 160, 68, 192, 69})
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) < 5 {
			return
		}
		defer goleak.VerifyNone(t, goleak.IgnoreCurrent())
		clk := clock.NewFake(t, time.Time{})
		n := NewNetwork(WithClock(clk), WithEventLog(64), WithSeed(int64(len(data))))
		cfg := NATConfig{
			Mapping:        Mapping(data[0] % 3),
			Filtering:      Filtering(data[1] % 3),
			PortAlloc:      []PortAlloc{Preserve, Sequential, Random, PreserveThenSequential, Pool(20000, 20063)}[data[2]%5],
			PortStep:       int(data[3]%3) + 1,
			MaxMappings:    int(data[4]%6) + 1,
			MappingTimeout: 5 * time.Second,
			Hairpin:        data[4]&0x80 != 0,
		}
		nat := n.NAT(cfg)
		var socks []*conn
		for i := range 3 {
			h := nat.Host()
			for j := range 2 {
				c, err := h.Listen("udp4", netip.AddrPortFrom(netip.Addr{}, uint16(3000+i*2+j)))
				if err != nil {
					t.Fatal(err)
				}
				socks = append(socks, c.(*conn))
			}
		}
		var remotes []*conn
		for i := range 2 {
			h := n.PublicHost(netip.IPv4Unspecified())
			for j := range 2 {
				c, err := h.Listen("udp4", netip.AddrPortFrom(h.Addrs()[0], uint16(1000+i*10+j)))
				if err != nil {
					t.Fatal(err)
				}
				remotes = append(remotes, c.(*conn))
			}
		}
		buf := make([]byte, 64)
		for _, op := range data[5:] {
			arg := int(op & 0x3f)
			switch op >> 6 {
			case 0: // outbound, possibly hairpinned to another mapping
				s := socks[arg%len(socks)]
				dst := remotes[(arg/len(socks))%len(remotes)].localAP()
				if ms := nat.Mappings(); arg&1 == 1 && len(ms) > 0 {
					dst = ms[arg%len(ms)].External
				}
				_, _ = s.writeTo([]byte{op}, dst)
			case 1: // inbound towards a live mapping, or to a guessed port
				checkInbound(t, nat, cfg.Filtering, socks, remotes[arg%len(remotes)], arg/len(remotes), op, buf)
			case 2: // time passes
				clk.Advance(time.Duration(arg) * 200 * time.Millisecond)
			case 3:
				if arg == 0 {
					nat.ExpireAll()
					break
				}
				for _, c := range slices.Concat(socks, remotes) {
					for len(c.inbox) > 0 {
						_, _, _ = c.readFrom(buf)
					}
				}
			}
			if st := nat.Stats(); st.MappingsActive > cfg.MaxMappings {
				t.Fatalf("%d active mappings > MaxMappings %d", st.MappingsActive, cfg.MaxMappings)
			}
		}
		if err := n.Close(); err != nil {
			t.Fatal(err)
		}
	})
}

// checkInbound sends from r to the k-th live mapping (or to a port without
// mapping) and checks that it is delivered exactly when the filter allows.
func checkInbound(t *testing.T, nat *NAT, f Filtering, socks []*conn, r *conn, k int, op byte, buf []byte) {
	t.Helper()
	ms := nat.Mappings()
	if len(ms) == 0 {
		_, _ = r.writeTo([]byte{op}, netip.AddrPortFrom(nat.ExternalIPs()[0], uint16(3000+k)))
		return
	}
	m := ms[k%len(ms)]
	src := r.localAP()
	var want bool
	switch f {
	case EIF:
		want = true
	case ADF:
		want = slices.ContainsFunc(m.Permits, func(p netip.AddrPort) bool { return p.Addr() == src.Addr() })
	default:
		want = slices.Contains(m.Permits, src)
	}
	var target *conn
	for _, s := range socks {
		if s.port == m.Internal.Port() && s.h.addrs[0] == m.Internal.Addr() {
			target = s
		}
	}
	if target == nil {
		t.Fatalf("no socket behind mapping %+v", m)
	}
	for len(target.inbox) > inboxPackets/2 { // keep room: a full queue drops by design
		_, _, _ = target.readFrom(buf)
	}
	before := len(target.inbox)
	_, _ = r.writeTo([]byte{op}, m.External)
	if got := len(target.inbox) > before; got != want {
		t.Fatalf("filter %v: inbound from %v to %v delivered=%v, want %v (mappings %+v)", f, src, m.External, got, want, ms)
	}
}
