package holepunch

import (
	"context"
	"net/netip"
	"time"

	"github.com/djylb/holepunch/internal/nat"
	"github.com/djylb/holepunch/internal/netaddr"
	"github.com/djylb/holepunch/internal/udpwire"
	"github.com/djylb/holepunch/protocol"
)

// Anchor refresh. Before the go of a round that
// aims at this side's next sequential ports, the server may ask for a
// refresh (punch_assist{kind: refresh}): two new sockets, refreshGap apart,
// each send one probe to the family's first global observer, marked with
// the SANDWICH TLV's refresh phases so that natprobe hands them to the
// coordinator. Only new sockets make new mappings, and only new mappings
// show where the allocator is now and how fast other hosts move it. Each
// socket is closed as soon as its probe left: the coordinator reads the
// mapping from natprobe, not from the ack.

// refreshGap spaces the two refresh probes. The coordinator measures the
// others' rate over the whole time since probing, so the gap need not be
// long enough to see other hosts allocate; it is kept short because the
// round waits for the second probe.
const refreshGap = 60 * time.Millisecond

// refreshAnchor runs the refresh of a's family on its own goroutine of the
// session group; it is dropped when the family has no global observer.
func (rt *runtime) refreshAnchor(a protocol.Assist) {
	fs := rt.fam(a.Family)
	if fs == nil || fs.primary == nil {
		return
	}
	obs, ok := globalObserver(fs.observers)
	if !ok {
		return
	}
	rt.g.Go("refresh:"+string(a.Family), func(ctx context.Context) {
		rt.refreshProbe(ctx, fs.primary, obs, a.Round, nat.RefreshFirst)
		t := rt.clk.NewTimer(refreshGap)
		defer t.Stop()
		select {
		case <-ctx.Done():
			return
		case <-t.C():
		}
		rt.refreshProbe(ctx, fs.primary, obs, a.Round, nat.RefreshSecond)
	})
}

// refreshProbe binds a new socket on the primary's IP, sends one refresh
// probe of phase from it through the gate's probe class (natprobe counts
// it against the session's probe budget) and closes it.
func (rt *runtime) refreshProbe(ctx context.Context, primary *udpSock, obs protocol.ObserverSpec, round, phase uint8) {
	s, err := rt.socks.open(ctx, primary.fam, netip.AddrPortFrom(primary.local.Addr(), 0), PurposeProbe, nat.IndexSandwich, extraRecvBuffer)
	if err != nil {
		return
	}
	defer rt.socks.release(s)
	h := udpwire.Header{Type: udpwire.TProbe, Cand: udpwire.NoCand, Aux: uint16(obs.ID)}
	t := udpwire.TLVs{}
	t.Sandwich.Round, t.Sandwich.Phase, t.Sandwich.Set = round, phase, true
	_ = rt.sender.Send(ctx, s, netaddr.Canon(obs.Addr), &h, &t, sendOpt{class: classProbe, stage: txProbe})
}

// globalObserver is the first main-group observer on a global address, the
// one a re-observation and a refresh probe go to: natprobe takes what an
// observer on a private address sees as LAN evidence only.
func globalObserver(observers []protocol.ObserverSpec) (protocol.ObserverSpec, bool) {
	for _, o := range observers {
		if nat.ScopeOf(o.Addr.Addr()) == nat.ScopeGlobal {
			return o, true
		}
	}
	return protocol.ObserverSpec{}, false
}
