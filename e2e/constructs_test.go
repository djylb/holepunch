package e2e

import (
	"math/rand/v2"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/djylb/holepunch/controlwire"
	"github.com/djylb/holepunch/nattest"
	"github.com/djylb/holepunch/protocol"
)

// Constructed conditions of the ablation and of the deliberately
// misclassified cells. nattest models NAT devices;
// these model what happens on the path or next to the NAT while a session
// runs, so that a cell can make round 1 fail, or make the NAT behave
// differently from what natprobe measured.

// firstRung reports whether a variant name is the first rung of its ladder
// ("easy_r1_direct", "pdf_x_seq_r1", ...): the cheap symmetric round every
// ladder starts with unless the strategy memory promoted a later one.
func firstRung(variant string) bool {
	i := strings.Index(variant, "_r1")
	return i >= 0 && (i+3 == len(variant) || variant[i+3] == '_')
}

// silenceRung silences the two peers toward each other while a side runs a
// round whose variant blocked selects: every packet a side sends to the
// peer's public addresses is lost on the path beyond its own outermost NAT,
// so the round neither connects nor reaches the peer's NAT, while the
// side's own NATs map every packet as they would on a real path that loses
// them: the coordinator counts those mappings
// (Mapped), and so does the allocator. The variant of round 1 is the
// summary's, that of a later round its go's; the silence follows each
// side's own control link.
func silenceRung(r *run, sides [2]*side, blocked func(variant string) bool) {
	for i := range 2 {
		peer := sides[1-i].publicIPs()
		toPeer := func(to netip.AddrPort) bool { return slices.Contains(peer, to.Addr().Unmap()) }
		outer := sides[i].nats[len(sides[i].nats)-1]
		apply := func(variant string) {
			if blocked(variant) {
				outer.DropUpstream(toPeer)
			} else {
				outer.DropUpstream(nil)
			}
		}
		r.taps[i].subscribe(toClient, controlwire.TypeProbeSummary, func(ev frameEvent) {
			if s, ok := ev.Msg.(*protocol.ProbeSummary); ok {
				apply(s.Plan.Round1.Variant)
			}
		})
		r.taps[i].subscribe(toClient, controlwire.TypePunchGo, func(ev frameEvent) {
			if g, ok := ev.Msg.(*protocol.PunchGo); ok && g.Plan != nil {
				apply(g.Plan.Variant)
			}
		})
	}
}

// oneWayLoss loses each packet from side from to side to with probability
// p, at the receiving socket (after the NATs, like a lossy last hop), for
// the whole session. The draws come from seed.
func oneWayLoss(sides [2]*side, from, to int, p float64, seed int64) {
	peer := sides[from].publicIPs()
	var mu sync.Mutex
	rng := rand.New(rand.NewPCG(uint64(seed), 0x6f6e652d776179))
	sides[to].net.dropFrom(func(src netip.AddrPort) bool {
		if !slices.Contains(peer, src.Addr().Unmap()) {
			return false
		}
		mu.Lock()
		defer mu.Unlock()
		return rng.Float64() < p
	})
}

// loadFirstPort is the first destination port of a neighbour's load; each
// packet goes to the next one, so that an endpoint-dependent NAT creates a
// new mapping — and allocates an external port — for every packet.
const loadFirstPort = 20000

// load puts other subscribers behind nat to work: a neighbour host on nat's LAN
// sends pps packets a second, each to a new destination. The load changes when
// side i's probe_summary is written — the end of what natprobe measured. With
// afterProbe it starts then and lasts until the run ends: natprobe measured the
// NAT quiet, and a sequential allocator moves pps ports a second while the
// session punches. Otherwise it runs from the start until then: natprobe
// measured the allocator moving, and it stands still while the session punches.
// Both are behaviour changing under load.
func (w *world) load(r *run, nat *nattest.NAT, i, pps int, afterProbe bool) {
	summary := r.taps[i].when(toClient, controlwire.TypeProbeSummary, nil)
	h := nat.Host()
	var dst netip.Addr
	for _, a := range w.server.Addrs() {
		if a.Is4() {
			dst = a
			break
		}
	}
	ctx := r.ctx[i]
	w.helpers.Add(1)
	go func() {
		defer w.helpers.Done()
		begin, end := (<-chan frameEvent)(nil), summary
		if afterProbe {
			begin, end = summary, nil
		}
		if begin != nil {
			select {
			case <-begin:
			case <-ctx.Done():
				return
			case <-w.quit:
				return
			}
		}
		pc, err := h.Listen("udp4", netip.AddrPort{})
		if err != nil {
			return
		}
		defer func() { _ = pc.Close() }()
		out := pc.(interface {
			WriteToUDPAddrPort([]byte, netip.AddrPort) (int, error)
		})
		tick := time.NewTicker(time.Second / time.Duration(pps))
		defer tick.Stop()
		for port := loadFirstPort; ; port++ {
			select {
			case <-tick.C:
			case <-end:
				return
			case <-ctx.Done():
				return
			case <-w.quit:
				return
			}
			if port > 0xFFFF {
				port = loadFirstPort
			}
			_, _ = out.WriteToUDPAddrPort([]byte{0}, netip.AddrPortFrom(dst, uint16(port)))
		}
	}()
}
