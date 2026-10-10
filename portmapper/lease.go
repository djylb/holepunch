package portmapper

import (
	"context"
	"sync"
	"time"

	"github.com/djylb/holepunch/internal/faultinject"
	"github.com/djylb/holepunch/internal/life"
	"github.com/djylb/holepunch/protocol"
)

// remover deletes a mapping at the gateway.
type remover interface {
	remove(ctx context.Context) error
}

// liveMapping is a mapping that a lease renews and finally deletes. Its
// methods are only called by the owning lease, never concurrently.
type liveMapping interface {
	remover
	// renew refreshes the mapping and returns the lifetime the gateway
	// granted.
	renew(ctx context.Context) (time.Duration, error)
}

// lease owns one mapping for the rest of its life: the renewal goroutine (if
// the mapping expires) and the final delete.
type lease struct {
	m    *Mapper
	live liveMapping
	info protocol.PortMappingInfo

	ctx    context.Context // child of the group's context; cancelled when release starts
	cancel context.CancelFunc
	done   chan struct{} // closed when the renewal goroutine has returned

	once sync.Once
	err  error
}

func newLease(m *Mapper, live liveMapping, info protocol.PortMappingInfo) *lease {
	ctx, cancel := context.WithCancel(m.g.Context())
	return &lease{m: m, live: live, info: info, ctx: ctx, cancel: cancel, done: make(chan struct{})}
}

// start launches the renewal goroutine. A mapping that does not expire (a
// permanent UPnP mapping) needs none.
func (l *lease) start() {
	if l.info.Lease <= 0 || !l.m.g.Go("portmap.renew", func(context.Context) { l.renewLoop() }) {
		close(l.done)
	}
}

// renewLoop refreshes the mapping at half its lifetime until release. A
// failed renewal is retried at a quarter of the lifetime: the gateway may
// have rebooted, and a renewal then re-creates the mapping. A panic stops
// the renewals; release still deletes the mapping.
func (l *lease) renewLoop() {
	defer close(l.done)
	lifetime := l.info.Lease
	t := l.m.clk.NewTimer(renewAfter(lifetime, true))
	defer t.Stop()
	for {
		select {
		case <-l.ctx.Done():
			return
		case <-t.C():
		}
		var granted time.Duration
		var err error
		if perr := life.Safe(pointRenew, func() {
			if err = faultinject.Point(pointRenew); err != nil {
				return
			}
			ctx, cancel := context.WithTimeout(l.ctx, l.m.cfg.AttemptTimeout)
			defer cancel()
			granted, err = l.live.renew(ctx)
		}); perr != nil {
			return
		}
		if err == nil && granted > 0 {
			lifetime = granted
		}
		t.Reset(renewAfter(lifetime, err == nil))
	}
}

// renewAfter is the delay before the next renewal of a mapping with the
// given lifetime: half of it after a success, a quarter after a failure, and
// never less than a second.
func renewAfter(lifetime time.Duration, ok bool) time.Duration {
	d := lifetime / 2
	if !ok {
		d = lifetime / 4
	}
	return max(d, time.Second)
}

// release stops the renewals and then deletes the mapping, within
// releaseTimeout. It is the release function Map returns.
func (l *lease) release() error { return l.releaseBy(time.Now().Add(releaseTimeout)) }

// releaseBy is release with an explicit deadline. It is idempotent and safe
// for concurrent use; every call returns the result of the first.
func (l *lease) releaseBy(deadline time.Time) error {
	l.once.Do(func() {
		if perr := life.Safe("portmap.release", func() { l.err = l.stopAndDelete(deadline) }); perr != nil {
			l.err = perr
		}
		l.m.forget(l)
	})
	return l.err
}

func (l *lease) stopAndDelete(deadline time.Time) error {
	l.cancel()
	ctx, cancel := context.WithDeadline(context.Background(), deadline)
	defer cancel()
	// Wait for the renewal goroutine, so that no renewal reaches the gateway
	// after the delete and re-creates the mapping. It returns as soon as its
	// request in flight sees the cancellation.
	select {
	case <-l.done:
	case <-ctx.Done():
		return errRenewStuck
	}
	return l.live.remove(ctx)
}
