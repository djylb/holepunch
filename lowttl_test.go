package holepunch

import (
	"context"
	"net"
	"net/netip"
	"slices"
	"sync"
	"testing"

	"github.com/djylb/holepunch/protocol"
)

// hopLog records the hop limits the client set on its sockets.
type hopLog struct {
	mu   sync.Mutex
	hops []int
}

func (l *hopLog) add(h int) {
	l.mu.Lock()
	l.hops = append(l.hops, h)
	l.mu.Unlock()
}

// low lists the low hops set, each once, in the order first set.
func (l *hopLog) low() []int {
	l.mu.Lock()
	defer l.mu.Unlock()
	var out []int
	for _, h := range l.hops {
		if h > 0 && !slices.Contains(out, h) {
			out = append(out, h)
		}
	}
	return out
}

// hopNet is a Network whose sockets log every SetHopLimit.
type hopNet struct {
	Network
	log *hopLog
}

func (n hopNet) ListenPacket(ctx context.Context, network string, laddr netip.AddrPort, purpose string) (net.PacketConn, error) {
	c, err := n.Network.ListenPacket(ctx, network, laddr, purpose)
	if err != nil {
		return nil, err
	}
	return hopConn{c, n.log}, nil
}

type hopConn struct {
	net.PacketConn
	log *hopLog
}

func (c hopConn) SetHopLimit(hops int) error {
	c.log.add(hops)
	return c.PacketConn.(HopLimiter).SetHopLimit(hops)
}

// A low-TTL stage's hop is its preferred hop when the session allows it,
// else the allowed hop nearest it, and the packets cycle through the allowed
// hops in their order.
func TestHopCycle(t *testing.T) {
	rt := &runtime{}
	rt.policy.LowTTLHops = []int{4, 7}
	for h, want := range map[int][]int{4: {4, 7}, 7: {7, 4}, 5: {4, 7}, 6: {7, 4}, 30: {7, 4}, 2: {4, 7}} {
		if got := rt.hopCycle(h); !slices.Equal(got, want) {
			t.Errorf("hop %d: %v want %v", h, got, want)
		}
	}
	rt.policy.LowTTLHops = []int{8, 4}
	if got := rt.hopCycle(6); !slices.Equal(got, []int{4, 8}) {
		t.Errorf("a tie takes the smaller hop: %v", got)
	}
	rt.policy.LowTTLHops = nil
	if got := rt.hopCycle(4); got != nil {
		t.Errorf("no allowed hop: %v", got)
	}
	if hopAt(nil, 3) != 0 || hopAt([]int{7, 4}, 3) != 4 {
		t.Error("hopAt")
	}
}

// The session's hops are the server's low_ttl_hops (default {4,7}) that the
// local policy also allows; with none left, low TTL is off for the session
// and the report says so.
func TestLowTTLHopsFromPolicy(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name          string
		server, local []int
		ttl           uint8
		want          []int
		caps          bool
	}{
		{"default set from the stage's hop", nil, nil, 7, []int{7, 4}, true},
		{"local subset", nil, []int{4}, 7, []int{4}, true},
		{"server set", []int{5, 9}, nil, 9, []int{9, 5}, true},
		{"empty intersection", nil, []int{9}, 7, nil, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			log := &hopLog{}
			var pol *protocol.Policy
			if tc.server != nil {
				pol = &protocol.Policy{LowTTLHops: tc.server}
			}
			_, rep, rr := soloRound(t, pol, func(o *Options) {
				o.Network = hopNet{o.Network, log}
				if tc.local != nil {
					o.Policy = &protocol.Policy{LowTTLHops: tc.local}
				}
			}, func(r *protocol.RoundPlan) {
				r.Sides[0].Stages[0].TTL = tc.ttl
				r.Sides[0].Stages[0].Repeats = 4
			}, nil)
			if len(rep.Caps.Families) != 1 || rep.Caps.Families[0].LowTTL != tc.caps {
				t.Fatalf("caps %+v", rep.Caps)
			}
			if rr.Families[0].Sent == 0 {
				t.Fatalf("nothing sent: %+v", rr)
			}
			if got := log.low(); !slices.Equal(got, tc.want) {
				t.Fatalf("low hops %v want %v", got, tc.want)
			}
		})
	}
}
