package natprobe

import (
	"context"
	"log/slog"
	"strings"
	"sync/atomic"
	"time"

	"github.com/djylb/holepunch/clock"
	"github.com/djylb/holepunch/internal/life"
)

// Defaults of the address lists that refresh themselves (STUNList,
// ServerAddrs).
const (
	defaultSTUNRefresh  = 6 * time.Hour
	defaultAddrsRefresh = 5 * time.Minute
	defaultRefreshRetry = time.Minute
)

// refresher is the schedule shared by STUNList and ServerAddrs: refresh
// every period, every retry instead while the last refresh left the list
// empty, until the context ends.
type refresher struct {
	clk    clock.Clock
	log    *slog.Logger
	period time.Duration
	retry  time.Duration
	done   atomic.Bool // a refresh has completed
}

func newRefresher(clk clock.Clock, log *slog.Logger, period, defPeriod, retry time.Duration) refresher {
	if clk == nil {
		clk = clock.System{}
	}
	if period <= 0 {
		period = defPeriod
	}
	if retry <= 0 {
		retry = min(defaultRefreshRetry, period)
	}
	return refresher{clk: clk, log: log, period: period, retry: retry}
}

// run calls refresh at once, unless one has already completed, and then
// after every period — retry while full reports an empty list — until ctx
// ends.
func (r *refresher) run(ctx context.Context, refresh func(context.Context), full func() bool) {
	if !r.done.Load() {
		refresh(ctx)
	}
	t := r.clk.NewTimer(r.wait(full()))
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C():
		}
		refresh(ctx)
		t.Reset(r.wait(full()))
	}
}

func (r *refresher) wait(full bool) time.Duration {
	if full {
		return r.period
	}
	return r.retry
}

// record calls the caller's Logger, whose handler is user code, inside a
// recover boundary. A multi-line error is joined onto one line.
func (r *refresher) record(level slog.Level, msg string, args ...any) {
	if r.log == nil {
		return
	}
	for i, a := range args {
		if err, ok := a.(error); ok {
			args[i] = strings.ReplaceAll(err.Error(), "\n", "; ")
		}
	}
	_ = life.Safe("natprobe/log", func() { r.log.Log(context.Background(), level, msg, args...) })
}
