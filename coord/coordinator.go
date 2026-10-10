package coord

import (
	"context"
	"errors"
	"fmt"
	"hash/maphash"
	"io"
	"slices"
	"sync"
	"time"

	"github.com/djylb/holepunch/internal/faultinject"
	"github.com/djylb/holepunch/internal/life"
	"github.com/djylb/holepunch/protocol"
)

// Coordinator timings.
const (
	housekeepEvery = 10 * time.Second // quota table, memory TTL and Registry sweeps
	closeBound     = 3 * time.Second  // Close's internal bound
	memorySweepMax = 1024             // memory entries scanned per housekeeping round
)

// Coordinator creates and supervises sessions. Its methods are safe for
// concurrent use.
type Coordinator struct {
	cfg     Config
	set     settings
	root    *life.Group // housekeeping and the event dispatcher
	limiter *limiter
	disp    *dispatcher // nil without an Observer
	ctr     counters
	salt    []byte // StrategyKey salt when Memory is not the built-in memory
	seed    maphash.Seed

	// Session groups derive from sessCtx; Close cancels it with ErrClosed,
	// which ends every session with server_shutdown.
	sessCtx        context.Context
	cancelSessions context.CancelCauseFunc

	randMu sync.Mutex // Config.Rand need not be safe for concurrent use

	mu      sync.Mutex
	closed  bool
	live    int           // sessions whose Done is not closed yet
	drained chan struct{} // closed once closed and live == 0
	drainOK bool
	index   [16]indexShard

	closeOnce sync.Once
	closeDone chan struct{}
	closeErr  error
}

type indexShard struct {
	mu sync.Mutex
	m  map[string]*Session
}

// New validates cfg and starts a Coordinator: its housekeeping goroutine and,
// with an Observer, its event dispatcher.
func New(cfg Config) (c *Coordinator, err error) {
	if perr := life.Safe("coord.new", func() { c, err = newCoordinator(cfg) }); perr != nil {
		return nil, fmt.Errorf("coord: new: %w", perr)
	}
	return c, err
}

// newCoordinator builds the Coordinator and starts its goroutines last, after
// everything that can fail (Config.Rand), so that a failed New leaves nothing
// running.
func newCoordinator(cfg Config) (*Coordinator, error) {
	set, err := newSettings(cfg)
	if err != nil {
		return nil, err
	}
	c := &Coordinator{
		cfg:       cfg,
		set:       set,
		root:      life.New(context.Background()),
		limiter:   newLimiter(set.limits, set.clock.Now()),
		seed:      maphash.MakeSeed(),
		drained:   make(chan struct{}),
		closeDone: make(chan struct{}),
	}
	switch m, ok := set.memory.(*memory); {
	case ok:
		c.salt = m.salt
	case len(cfg.StrategySalt) > 0:
		c.salt = slices.Clone(cfg.StrategySalt)
	default:
		c.salt = make([]byte, memSaltSize)
		if err := c.readRand(c.salt); err != nil {
			return nil, err
		}
	}
	for i := range c.index {
		c.index[i].m = make(map[string]*Session)
	}
	c.sessCtx, c.cancelSessions = context.WithCancelCause(context.Background())
	if cfg.Observer != nil {
		c.disp = &dispatcher{
			q:       make(chan Event, set.limits.ObserverQueue),
			fn:      cfg.Observer,
			dropped: func() { c.ctr.eventsDropped.Add(1) },
			panics:  func() { c.ctr.panics.Add(1) },
		}
		c.root.Go("coord.observer", c.disp.run)
	}
	c.root.Go("coord.housekeeping", c.housekeep)
	return c, nil
}

// readRand fills b from Config.Rand.
func (c *Coordinator) readRand(b []byte) error {
	c.randMu.Lock()
	defer c.randMu.Unlock()
	_, err := io.ReadFull(c.set.rand, b)
	return err
}

// Lookup returns the live session with the given id.
func (c *Coordinator) Lookup(sessionID string) (*Session, bool) {
	sh := c.shard(sessionID)
	sh.mu.Lock()
	defer sh.mu.Unlock()
	s, ok := sh.m[sessionID]
	return s, ok
}

// Len returns the number of live sessions.
func (c *Coordinator) Len() int {
	n := 0
	for i := range c.index {
		sh := &c.index[i]
		sh.mu.Lock()
		n += len(sh.m)
		sh.mu.Unlock()
	}
	return n
}

// Stats returns a snapshot of the coordinator's counters.
func (c *Coordinator) Stats() Stats {
	s := c.ctr.snapshot()
	s.SessionsActive = int64(c.Len())
	s.KeyEntries, s.ActiveByKey, s.KeysEvicted, s.KeyTableFull = c.limiter.keyStats()
	if m, ok := c.set.memory.(*memory); ok {
		s.MemoryEntries = int64(m.len())
	}
	return s
}

// Memory returns the strategy memory, for callers that report outcomes of
// their own (an upper-layer transport that failed on a confirmed path).
func (c *Coordinator) Memory() StrategyMemory { return c.set.memory }

// Close ends every session with server_shutdown — sessions still before the
// punch get punch_abort{server_shutdown}, punching and confirming sessions
// only have their links closed — and stops the
// coordinator's goroutines. It waits at most 3 s. It is idempotent and safe
// for concurrent use: every caller waits for the first call's shutdown and
// gets its result. NewSession and Attach return ErrClosed afterwards.
//
// Close returns nil, or what went wrong, in the order of the shutdown's steps:
// a panic as a *life.PanicError, and ErrShutdownTimeout when sessions or
// goroutines stuck in user code were left behind (counted in Stats.Stuck). A
// single failure is returned as it is, several are joined (errors.Join). A
// panic never reaches the caller and skips no later step: it is also counted in
// Stats.Panics and reported as an EvInternalError event, and the shutdown still
// ends every session and joins the coordinator's goroutines before Close
// returns it.
func (c *Coordinator) Close() error {
	c.closeOnce.Do(func() {
		// Deferred so that later and concurrent callers are released
		// whatever happens in the shutdown.
		defer close(c.closeDone)
		c.closeErr = c.shutdown()
	})
	<-c.closeDone
	return c.closeErr
}

// shutdown is Close's work. Every step runs in its own recover boundary, so a
// failing step skips no later one: the sessions are always ended and the
// root group always closed.
func (c *Coordinator) shutdown() error {
	deadline := time.Now().Add(closeBound)
	var errs closeErrs
	drained := false
	c.closeStep(&errs, func() {
		c.mu.Lock()
		defer c.mu.Unlock()
		c.closed = true
		c.checkDrained()
	})
	c.closeStep(&errs, func() { errs.add(faultinject.Point(fiClose)) })
	c.closeStep(&errs, func() { c.cancelSessions(&ReasonError{Reason: protocol.ReasonServerShutdown}) })
	c.closeStep(&errs, func() { drained = c.awaitDrained(deadline) })
	c.closeStep(&errs, func() { _ = c.root.Close(max(time.Until(deadline), time.Millisecond)) })
	c.closeStep(&errs, func() {
		c.mu.Lock()
		stuck := c.live
		c.mu.Unlock()
		stuck += c.root.Stats().Leaked
		if !drained || stuck > 0 {
			c.ctr.stuck.Add(int64(stuck))
			errs.add(ErrShutdownTimeout)
		}
	})
	return errs.err()
}

// closeStep runs one step of Close in a recover boundary; a panic is
// reported, counted and kept for Close's result.
func (c *Coordinator) closeStep(errs *closeErrs, fn func()) {
	if err := life.Safe(fiClose, fn); err != nil {
		c.noteCallbackPanic("", err)
		errs.add(err)
	}
}

// closeErrs collects the failures of Close's steps in order.
type closeErrs []error

func (e *closeErrs) add(err error) {
	if err != nil {
		*e = append(*e, err)
	}
}

// err is nil, the only failure as it is, or every failure joined.
func (e *closeErrs) err() error {
	if len(*e) == 1 {
		return (*e)[0]
	}
	return errors.Join(*e...)
}

// awaitDrained waits until every session is done or the deadline passes, and
// reports whether they all are.
func (c *Coordinator) awaitDrained(deadline time.Time) bool {
	t := time.NewTimer(time.Until(deadline))
	defer t.Stop()
	select {
	case <-c.drained:
		return true
	case <-t.C:
		return false
	}
}

// checkDrained closes drained once the coordinator is closed and every
// session is done. Callers hold c.mu.
func (c *Coordinator) checkDrained() {
	if c.closed && c.live == 0 && !c.drainOK {
		c.drainOK = true
		close(c.drained)
	}
}

// sessionGone is called when a session's Done closes.
func (c *Coordinator) sessionGone() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.live--
	c.checkDrained()
}

func (c *Coordinator) shard(id string) *indexShard {
	return &c.index[maphash.String(c.seed, id)%uint64(len(c.index))]
}

// unindex removes s from the index if it is still the session of its id.
func (c *Coordinator) unindex(s *Session) {
	sh := c.shard(s.id)
	sh.mu.Lock()
	defer sh.mu.Unlock()
	if sh.m[s.id] == s {
		delete(sh.m, s.id)
	}
}

func (c *Coordinator) emit(ev Event) { c.disp.emit(ev) }

// noteCallbackPanic counts a panic of user code and reports it as an event.
func (c *Coordinator) noteCallbackPanic(sessionID string, err error) {
	c.ctr.panics.Add(1)
	ev := Event{Kind: EvInternalError, At: c.set.clock.Now(), SessionID: sessionID, Detail: err.Error()}
	var pe *life.PanicError
	if errors.As(err, &pe) {
		ev.Detail = pe.Where()
		ev.Data = PanicInfo{Value: pe.Error(), Stack: pe.Stack()}
	}
	c.emit(ev)
}

// housekeep sweeps the quota table, the strategy memory and the Registry
// every 10 s until the coordinator closes.
func (c *Coordinator) housekeep(ctx context.Context) {
	t := c.set.clock.NewTimer(housekeepEvery)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C():
			if err := life.Safe("coord.housekeeping", c.sweep); err != nil {
				c.noteCallbackPanic("", err)
			}
			t.Reset(housekeepEvery)
		}
	}
}

// sweeper is the optional Sweep of a StrategyMemory (the built-in one has it).
type sweeper interface {
	Sweep(now time.Time, max int) int
}

func (c *Coordinator) sweep() {
	now := c.set.clock.Now()
	c.limiter.sweep(now)
	if m, ok := c.set.memory.(sweeper); ok {
		m.Sweep(now, memorySweepMax)
	}
	if reg := c.cfg.Registry; reg != nil && !c.cfg.DisableRegistrySweep {
		reg.Sweep(now)
	}
}
