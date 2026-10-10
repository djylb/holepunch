package natprobe

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestResolveSTUN(t *testing.T) {
	names := map[string][]netip.Addr{
		"dual.example":    {netip.MustParseAddr("192.168.1.9"), netip.MustParseAddr("2001:db8::1"), netip.MustParseAddr("198.51.100.1")},
		"v4.example":      {netip.MustParseAddr("198.51.100.2"), netip.MustParseAddr("198.51.100.3")},
		"private.example": {netip.MustParseAddr("10.0.0.1"), netip.MustParseAddr("100.64.0.1")},
	}
	lookup := func(ctx context.Context, network, host string) ([]netip.Addr, error) {
		if network != "ip" {
			return nil, fmt.Errorf("network %q", network)
		}
		switch host {
		case "panic.example":
			panic("boom")
		case "slow.example":
			<-ctx.Done()
			return nil, ctx.Err()
		case "delayed.example":
			t := time.NewTimer(30 * time.Millisecond)
			defer t.Stop()
			select {
			case <-t.C:
				return []netip.Addr{netip.MustParseAddr("198.51.100.7")}, nil
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}
		if a, ok := names[host]; ok {
			return a, nil
		}
		return nil, errors.New("no such host")
	}
	servers := []string{"dual.example:3478", "203.0.113.9:19302", "v4.example:3478", "[2001:db8::2]:3478", "private.example:3478",
		"missing.example:3478", "panic.example:3478", "slow.example:3478", "no-port", "198.51.100.4:0", "192.168.1.1:3478", "v4.example:3478",
		"delayed.example:3478"}
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	got, err := ResolveSTUN(ctx, lookup, servers)
	want := []netip.AddrPort{
		netip.MustParseAddrPort("198.51.100.1:3478"), netip.MustParseAddrPort("203.0.113.9:19302"),
		netip.MustParseAddrPort("198.51.100.2:3478"), netip.MustParseAddrPort("198.51.100.7:3478"),
		netip.MustParseAddrPort("[2001:db8::1]:3478"), netip.MustParseAddrPort("[2001:db8::2]:3478"),
	}
	if !slices.Equal(got, want) {
		t.Fatalf("addresses %v, want %v", got, want)
	}
	for _, s := range []string{"private.example", "missing.example", "panic.example", "slow.example", "no-port", "198.51.100.4:0", "192.168.1.1:3478"} {
		if err == nil || !strings.Contains(err.Error(), s) {
			t.Errorf("error %v does not name %s", err, s)
		}
	}

	// At most 8 of a family: what a client asks.
	var many []string
	for i := range 10 {
		many = append(many, fmt.Sprintf("198.51.100.%d:3478", 10+i))
	}
	if got, err := ResolveSTUN(context.Background(), lookup, many); err != nil || len(got) != maxSTUNPerFamily || got[0].Addr() != netip.MustParseAddr("198.51.100.10") {
		t.Fatalf("%v, %v", got, err)
	}
	if n := len(DefaultSTUNServers()); n < maxSTUNPerFamily {
		t.Fatalf("%d default servers", n)
	}
}
