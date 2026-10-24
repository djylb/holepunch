package hostaddr

import (
	"context"
	"slices"
	"time"
)

// DefaultWatchInterval is Watch's interval when it is given none.
const DefaultWatchInterval = 2 * time.Second

// Watch reads List every interval (DefaultWatchInterval when interval ≤ 0)
// and calls changed with the usable addresses (Addr.Usable) each time they
// differ from the previous read: an address came, went, or moved to another
// interface or kind — a network change, after which a peer-to-peer program
// looks for new paths. The first read is the reference and is not reported;
// a read that fails is skipped. Watch blocks until ctx ends, calling changed
// on its own goroutine: start it on a goroutine of the caller's.
func Watch(ctx context.Context, interval time.Duration, changed func([]Addr)) {
	watch(ctx, interval, List, changed)
}

func watch(ctx context.Context, interval time.Duration, list func() ([]Addr, error), changed func([]Addr)) {
	if interval <= 0 {
		interval = DefaultWatchInterval
	}
	read := func() ([]Addr, bool) {
		all, err := list()
		if err != nil {
			return nil, false
		}
		out := slices.DeleteFunc(all, func(a Addr) bool { return !a.Usable() })
		slices.SortFunc(out, compareAddr)
		return slices.Compact(out), true
	}
	last, ok := read()
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		cur, read := read()
		switch {
		case !read:
		case !ok:
			last, ok = cur, true // the first good read is the reference
		case !slices.Equal(cur, last):
			last = cur
			changed(slices.Clone(cur))
		}
	}
}

// compareAddr orders addresses by prefix, interface and kind.
func compareAddr(a, b Addr) int {
	if c := a.Prefix.Addr().Compare(b.Prefix.Addr()); c != 0 {
		return c
	}
	if c := a.Prefix.Bits() - b.Prefix.Bits(); c != 0 {
		return c
	}
	if a.Interface != b.Interface {
		if a.Interface < b.Interface {
			return -1
		}
		return 1
	}
	return int(a.Kind) - int(b.Kind)
}
