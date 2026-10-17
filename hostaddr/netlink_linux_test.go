package hostaddr

import (
	"net"
	"net/netip"
	"slices"
	"testing"
)

// The netlink address dump — what Android 11 and later leave an app — lists
// the addresses package net lists, by interface index, with the IPv4
// labels as names and the loopback flag.
func TestInterfacesFallback(t *testing.T) {
	want, err := net.Interfaces()
	if err != nil {
		t.Skip(err)
	}
	ifaces, addrs, err := interfacesFallback()
	if err != nil {
		t.Fatal(err)
	}
	if len(ifaces) != len(addrs) {
		t.Fatalf("%d interfaces, %d address lists", len(ifaces), len(addrs))
	}
	got := map[int][]netip.Prefix{}
	for i, ifc := range ifaces {
		got[ifc.Index] = addrs[i]
	}
	for _, w := range want {
		list, err := w.Addrs()
		if err != nil {
			continue
		}
		var exp []netip.Prefix
		for _, a := range list {
			if p, ok := prefixOf(a); ok {
				exp = append(exp, p)
			}
		}
		g := got[w.Index]
		for _, p := range exp {
			if !slices.Contains(g, p) {
				t.Errorf("%s: %v missing from the dump %v", w.Name, p, g)
			}
		}
		if len(exp) == 0 {
			continue
		}
		i := slices.IndexFunc(ifaces, func(f net.Interface) bool { return f.Index == w.Index })
		if f := ifaces[i]; f.Flags&net.FlagLoopback != w.Flags&net.FlagLoopback || f.Name != "" && f.Name != w.Name {
			t.Errorf("%s: dump says %q flags %v", w.Name, f.Name, f.Flags)
		}
	}
	t.Logf("%d interfaces with addresses", len(ifaces))
}
