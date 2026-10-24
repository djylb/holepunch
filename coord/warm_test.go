package coord_test

import (
	"testing"

	"github.com/djylb/holepunch"
	"github.com/djylb/holepunch/coord"
	"github.com/djylb/holepunch/nattest"
)

// TestE2EWarm: by default, the first session of two clients behind
// cone NATs starts cold — the traits memory knows neither yet — and teaches
// the memory their mappings; the next session of the same clients is
// planned on their early reports, and connects.
func TestE2EWarm(t *testing.T) {
	w := newE2EWorld(t, true)
	hosts := [2]*nattest.Host{w.n.NAT(nattest.PortRestricted()).Host(), w.n.NAT(nattest.PortRestricted()).Host()}
	opts := coord.SessionOptions{ClientKeys: [2]string{"alice", "bob"}}
	first, _ := w.punchWith(opts, hosts, [2]holepunch.PortMapper{})
	if first.Warm != [2]coord.WarmStart{coord.WarmCold, coord.WarmCold} {
		t.Fatalf("first session warm %v", first.Warm)
	}
	second, _ := w.punchWith(opts, hosts, [2]holepunch.PortMapper{})
	if second.Warm != [2]coord.WarmStart{coord.WarmHit, coord.WarmHit} {
		t.Fatalf("second session warm %v", second.Warm)
	}
	t.Logf("summary after creation: cold %v, warm %v", first.Timing.Summary.Sub(first.Timing.Created), second.Timing.Summary.Sub(second.Timing.Created))
}
