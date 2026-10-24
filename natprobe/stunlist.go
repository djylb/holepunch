package natprobe

import (
	"context"
	"log/slog"
	"net/netip"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/djylb/holepunch/clock"
)

// STUNListConfig configures a STUNList.
type STUNListConfig struct {
	// Servers are the STUN servers as ResolveSTUN takes them: host:port or
	// ip:port (stun.DefaultServers, for example).
	Servers []string
	// Lookup resolves the names; nil uses the system resolver.
	Lookup LookupFunc
	// Refresh is how often the names are resolved again; 0 means 6 h.
	Refresh time.Duration
	// Retry replaces Refresh while the list is empty; 0 means 1 min (at
	// most Refresh).
	Retry time.Duration
	// Clock schedules the refreshes; nil uses the system clock.
	Clock clock.Clock
	// Logger, optional, receives every resolution at Info and the servers
	// left out at Warn.
	Logger *slog.Logger
}

// STUNList keeps ResolveSTUN's result fresh for a long-running server: the
// addresses behind a STUN server's name change over time. Run resolves the
// servers again every Refresh; Addrs returns the latest addresses, for
// ProbeSpec.STUN (SpecSource does that). A resolution that finds no address
// keeps the previous ones. The methods are safe for concurrent use, and a
// nil *STUNList holds no address.
type STUNList struct {
	cfg STUNListConfig
	r   refresher
	mu  sync.Mutex // serializes Refresh: a slow resolution never replaces a later one
	cur atomic.Pointer[[]netip.AddrPort]
}

// NewSTUNList returns a list of cfg's servers that has not resolved them
// yet: call Refresh for a first resolution before serving, or let Run do it.
func NewSTUNList(cfg STUNListConfig) *STUNList {
	cfg.Servers = slices.Clone(cfg.Servers)
	return &STUNList{cfg: cfg, r: newRefresher(cfg.Clock, cfg.Logger, cfg.Refresh, defaultSTUNRefresh, cfg.Retry)}
}

// Addrs returns the latest addresses (a copy); nil before the first
// resolution that found any.
func (l *STUNList) Addrs() []netip.AddrPort {
	if l == nil {
		return nil
	}
	if p := l.cur.Load(); p != nil {
		return slices.Clone(*p)
	}
	return nil
}

// Refresh resolves the servers now (ResolveSTUN) and returns its error,
// which names the servers left out. The addresses found replace the
// current ones unless there are none.
func (l *STUNList) Refresh(ctx context.Context) error {
	if l == nil {
		return nil
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	addrs, err := ResolveSTUN(ctx, l.cfg.Lookup, l.cfg.Servers)
	if err != nil {
		l.r.record(slog.LevelWarn, "natprobe: STUN servers left out", "err", err)
	}
	if len(addrs) > 0 {
		l.cur.Store(&addrs)
	}
	l.r.done.Store(true)
	l.r.record(slog.LevelInfo, "natprobe: STUN servers resolved", "addrs", l.Addrs())
	return err
}

// Run resolves the servers at once, unless Refresh already did, and then
// every Refresh (Retry while the list is empty) until ctx ends. It blocks:
// start it on a goroutine of the caller's.
func (l *STUNList) Run(ctx context.Context) {
	if l == nil {
		return
	}
	l.r.run(ctx, func(ctx context.Context) { _ = l.Refresh(ctx) }, func() bool { return l.cur.Load() != nil })
}
