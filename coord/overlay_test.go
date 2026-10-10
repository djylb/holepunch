package coord

import (
	"net/netip"
	"slices"
	"testing"

	"github.com/djylb/holepunch/coord/internal/simclient"
	"github.com/djylb/holepunch/protocol"
)

// TestSharedOverlay checks the coordinator's side of overlay endpoints: a side's
// overlay addresses reach its peer as overlay endpoints at its primary
// socket's port, and the first round aims at them, only when both sides
// reported some (pair.shared_overlay); with one side's alone the peer never
// sees them.
func TestSharedOverlay(t *testing.T) {
	ovl := [2]netip.Addr{netip.MustParseAddr("100.101.0.1"), netip.MustParseAddr("100.101.0.2")}
	for _, both := range []bool{true, false} {
		r := newRig(t)
		p := r.pair(SessionOptions{})
		for i := range 2 {
			f := fam(i, simclient.OpenTraits)
			if i == 0 || both {
				f.Overlay = []netip.Addr{ovl[i]}
			}
			p.report(i, f)
		}
		for i := range 2 {
			sum := expect[protocol.ProbeSummary](t, p.cl[i])
			if sum.Pair.SharedOverlay[protocol.FamilyUDP4] != both {
				t.Fatalf("both %v: pair %+v", both, sum.Pair)
			}
			seen := slices.ContainsFunc(sum.Peer.Families[0].Endpoints, func(e protocol.Endpoint) bool {
				return e.Source == protocol.EndpointOverlay && e.Addr.Addr() == ovl[1-i] && !e.Verified
			})
			aimed := slices.ContainsFunc(targetsOf(sum.Plan.Round1), func(a netip.AddrPort) bool { return a.Addr() == ovl[1-i] })
			if seen != both || aimed != both || hasSource(sum.Peer, protocol.EndpointOverlay) != both {
				t.Fatalf("both %v role %d: overlay endpoint %v, aimed %v; peer %+v; plan %+v",
					both, i, seen, aimed, sum.Peer.Families[0].Endpoints, sum.Plan.Round1)
			}
		}
		p.s.Abort(protocol.ReasonCanceled, "")
		r.wait(p.s)
	}
}
