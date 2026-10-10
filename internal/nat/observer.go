package nat

import (
	"net/netip"

	"github.com/djylb/holepunch/protocol"
)

// maxObservers bounds the observers of one table. punch_start carries at
// most 16; a server-side table learns its observers from natprobe's slots,
// which a Server keeps to 16 per family as well, so 32 only guards against a
// Registry shared by several Servers.
const maxObservers = 32

// Observer describes one natprobe observer of the table's family.
type Observer struct {
	ID    uint8          // ObserverSpec.id = group*8 + port index
	Addr  netip.AddrPort // advertised address; zero in server-side tables, which only know ids
	Group uint8          // same group = same server public IP
	Alt   bool           // second-IP (change-IP) group
	Scope Scope          // scope of the advertised address
}

// Observers returns the observers of family f in punch_start.probe:
// IPv4-mapped addresses are unmapped, addresses of another family or
// without a scope (unspecified, multicast, broadcast) are skipped, and a
// repeated id or address keeps its first entry.
func Observers(f protocol.Family, specs []protocol.ObserverSpec) []Observer {
	var out []Observer
	for _, s := range specs {
		a := unmap(s.Addr)
		if !usableIn(f, a) || ScopeOf(a.Addr()) == ScopeNone || len(out) == maxObservers {
			continue
		}
		dup := false
		for _, o := range out {
			dup = dup || o.ID == s.ID || o.Addr == a
		}
		if !dup {
			out = append(out, Observer{ID: s.ID, Addr: a, Group: s.Group, Alt: s.Alt, Scope: ScopeOf(a.Addr())})
		}
	}
	return out
}
