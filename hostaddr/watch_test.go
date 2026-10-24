package hostaddr

import (
	"context"
	"errors"
	"net/netip"
	"sync"
	"testing"
	"time"
)

// TestWatch: Watch reports a change of the usable addresses once, ignores
// down and loopback addresses and failed reads, and returns when ctx ends.
func TestWatch(t *testing.T) {
	lan := Addr{Prefix: netip.MustParsePrefix("192.168.1.10/24"), Interface: "eth0", Up: true, Kind: LAN}
	lo := Addr{Prefix: netip.MustParsePrefix("127.0.0.1/8"), Interface: "lo", Up: true, Kind: Loopback}
	down := Addr{Prefix: netip.MustParsePrefix("10.0.0.2/24"), Interface: "eth1", Kind: LAN}
	wifi := Addr{Prefix: netip.MustParsePrefix("192.168.8.20/24"), Interface: "wlan0", Up: true, Kind: LAN}
	reads := []func() ([]Addr, error){
		func() ([]Addr, error) { return []Addr{lan, lo}, nil },
		func() ([]Addr, error) { return []Addr{lo, lan, down}, nil }, // unchanged
		func() ([]Addr, error) { return nil, errors.New("busy") },    // skipped
		func() ([]Addr, error) { return []Addr{wifi, lan}, nil },     // changed
	}
	var (
		mu sync.Mutex
		n  int
	)
	list := func() ([]Addr, error) {
		mu.Lock()
		defer mu.Unlock()
		i := min(n, len(reads)-1)
		n++
		return reads[i]()
	}
	ctx, cancel := context.WithCancel(context.Background())
	got := make(chan []Addr, 4)
	done := make(chan struct{})
	go func() {
		defer close(done)
		watch(ctx, time.Millisecond, list, func(a []Addr) { got <- a })
	}()
	select {
	case a := <-got:
		if len(a) != 2 || a[0] != lan || a[1] != wifi {
			t.Fatalf("changed %v", a)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no change reported")
	}
	time.Sleep(20 * time.Millisecond) // the last read repeats: no further report
	cancel()
	<-done
	if len(got) != 0 {
		t.Fatalf("reported again: %v", <-got)
	}
}
