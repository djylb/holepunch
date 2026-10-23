package e2e

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/djylb/holepunch"
	"github.com/djylb/holepunch/clock"
	"github.com/djylb/holepunch/coord"
	"github.com/djylb/holepunch/internal/ablation"
	"github.com/djylb/holepunch/nattest"
	"github.com/djylb/holepunch/protocol"
)

// roles in index order: 0 is the initiator, 1 the responder.
var roles = [2]protocol.Role{protocol.RoleInitiator, protocol.RoleResponder}

// Control link delays (10–40 ms).
const (
	ctlMin = 10 * time.Millisecond
	ctlMax = 40 * time.Millisecond
)

// sessionCap bounds a whole session from the test's side: above the
// library's session cap T for the e2e timeouts (about 43 s) and
// for the default ones of the default-timeout comparison (71 s).
const sessionCap = 90 * time.Second

// sessionSpec configures one session between two sides.
type sessionSpec struct {
	ablation     ablation.Set
	ctlDelay     [2]time.Duration // one-way delays of the control links; 0 draws one in [10, 40] ms
	ctlJitter    time.Duration
	ctlBuffer    [2]int        // pipe buffer per direction; 0 = nattest's default
	late         time.Duration // the responder joins this much later
	lightTaps    bool          // taps that only count frames (load tests)
	timeouts     *protocol.Timeouts
	clientPolicy [2]*protocol.Policy
	onProgress   [2]func(protocol.Progress)
	clock        [2]clock.Clock
	// maxPaths is both clients' Options.MaxPaths; 0 is one path.
	maxPaths int
	// background runs the session in Background mode: the coordinator
	// offers it and both clients accept it.
	background bool
	// prepare runs once the links exist and before anything is attached:
	// fault tests arm their taps and triggers here.
	prepare func(r *run)
	// onReturn runs on a side's goroutine right after its Punch
	// returned.
	onReturn [2]func(r *run)
}

// sideResult is what one client produced.
type sideResult struct {
	sess     *holepunch.Session
	err      error
	herr     *holepunch.Error
	start    time.Time
	end      time.Time
	diag     holepunch.Diagnostics
	host     nattest.HostStats // snapshot once both clients returned, before any use of the socket
	filtered uint64
	scanBans uint64
	attach   error // coord Attach error
	inflight int   // reads in flight on the control conn after return
	rdl, wdl time.Time
	// handed is the application's view of the winning socket, marked as
	// handed over the moment Punch returned; markErr is why
	// it could not be marked. extra are the views of the extra paths'
	// sockets, by Result.ExtraPaths; nil where a path shares the
	// primary path's socket.
	handed  nattest.Conn
	extra   []nattest.Conn
	markErr error
}

// ok reports a success.
func (s *sideResult) ok() bool { return s.err == nil && s.sess != nil }

// reason is the side's Reason, or "" on success.
func (s *sideResult) reason() protocol.Reason {
	if s.herr != nil {
		return s.herr.Reason
	}
	if s.err != nil {
		return "error"
	}
	return ""
}

// dur is the time Punch took.
func (s *sideResult) dur() time.Duration { return s.end.Sub(s.start) }

// run is one session in progress and, once finished, its outcome.
type run struct {
	w     *world
	sides [2]*side
	spec  sessionSpec
	s     *coord.Session
	taps  [2]*tap
	pipes [2]*nattest.PipeConn // the clients' ends
	spies [2]*ctlSpy
	ctx   [2]context.Context
	stop  [2]context.CancelFunc
	delay [2]time.Duration

	out   [2]sideResult
	res   coord.Result
	resOK bool
	done  bool // the coordinator's session ended within the cap
	// skipWinnerCheck: a fault broke the winning path after the handover, so
	// the winner cannot carry the check packet.
	skipWinnerCheck bool
	// crashed marks a side whose host crashed: its sockets are gone.
	crashed [2]bool
}

// cancel cancels a client's context (the cancel fault).
func (r *run) cancel(i int) { r.stop[i]() }

// newRun creates the session and its links without attaching anything.
func newRun(w *world, sides [2]*side, spec sessionSpec) (*run, error) {
	r := &run{w: w, sides: sides, spec: spec}
	so := coord.SessionOptions{Parent: ablation.With(context.Background(), spec.ablation), Timeouts: spec.timeouts}
	if spec.background {
		so.Mode = protocol.ModeBackground
	}
	s, err := w.co.NewSession(so)
	if err != nil {
		return nil, fmt.Errorf("new session: %w", err)
	}
	r.s = s
	for i := range 2 {
		r.delay[i] = spec.ctlDelay[i]
		if r.delay[i] == 0 {
			r.delay[i] = w.delay(ctlMin, ctlMax)
		}
		cli, srv := w.n.Pipe(nattest.PipeConfig{A: sides[i].host, B: w.server, DelayAB: r.delay[i], DelayBA: r.delay[i],
			Jitter: spec.ctlJitter, BufferBytes: spec.ctlBuffer[i]})
		r.pipes[i], r.taps[i], r.spies[i] = cli, newTap(srv), &ctlSpy{PipeConn: cli}
		r.taps[i].light = spec.lightTaps
		r.ctx[i], r.stop[i] = context.WithTimeout(ablation.With(context.Background(), spec.ablation), sessionCap)
	}
	return r, nil
}

// execute attaches both sides, runs both clients and waits for everything
// to end; it never fails the test itself.
func (r *run) execute() {
	if r.spec.prepare != nil {
		r.spec.prepare(r)
	}
	var wg sync.WaitGroup
	for i := range 2 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if i == 1 && r.spec.late > 0 {
				time.Sleep(r.spec.late)
			}
			r.client(i)
		}()
	}
	wg.Wait()
	for i := range 2 {
		r.out[i].host = r.sides[i].host.Stats()
		r.out[i].filtered, r.out[i].scanBans = r.sides[i].natStats()
		r.out[i].inflight, r.out[i].rdl, r.out[i].wdl = r.spies[i].returned()
	}
	select {
	case <-r.s.Done():
		r.done = true
	case <-time.After(scaled(10 * time.Second)):
	}
	r.res, r.resOK = r.s.Result()
	if r.done {
		r.w.waitResult(r.s.ID(), scaled(time.Second))
	}
	for i := range 2 {
		r.stop[i]()
	}
}

// client attaches one side to the coordinator and runs its Punch.
func (r *run) client(i int) {
	o := &r.out[i]
	o.start = time.Now()
	if err := r.s.Attach(roles[i], r.taps[i], coord.AttachOptions{Security: protocol.ControlSecurityInsecureForTesting}); err != nil {
		o.attach = err
		_ = r.taps[i].Close()
	}
	// The suite measures hole punching, never a tunnel: overlay addresses
	// are excluded.
	opts := holepunch.Options{
		ControlSecurity: protocol.ControlSecurityInsecureForTesting, Network: r.sides[i].net, TransportMode: "quic",
		Policy: r.spec.clientPolicy[i], OnProgress: r.spec.onProgress[i], Clock: r.spec.clock[i], ExcludeOverlay: true,
		MaxPaths: r.spec.maxPaths,
	}
	if r.spec.background {
		opts.AcceptBackground = true
	}
	if m := r.sides[i].mapper; m != nil {
		opts.PortMapper = m
	}
	if r.sides[i].pm != nil {
		opts.PortMapper = r.sides[i].pm
	}
	o.sess, o.err = holepunch.Punch(r.ctx[i], r.spies[i], opts)
	o.end = time.Now()
	if o.err == nil {
		// From here on every library call on the winning socket counts as a
		// call after the handover.
		o.handed, o.markErr = r.sides[i].host.MarkHandover(o.sess.Result().Path.LocalAddr)
		for k, p := range o.sess.Result().ExtraPaths {
			var h nattest.Conn
			if o.markErr == nil && o.sess.Result().ExtraPaths[k].Conn != o.sess.PacketConn() {
				h, o.markErr = r.sides[i].host.MarkHandover(p.LocalAddr)
			}
			o.extra = append(o.extra, h)
		}
	}
	if f := r.spec.onReturn[i]; f != nil {
		f(r)
	}
	if o.err != nil {
		errors.As(o.err, &o.herr)
		if o.herr != nil && o.herr.Diagnostics != nil {
			o.diag = *o.herr.Diagnostics
		}
	} else {
		o.diag = o.sess.Diagnostics()
	}
}

// closeSessions closes the clients' winning sockets.
func (r *run) closeSessions() error {
	var errs []error
	for i := range 2 {
		if s := r.out[i].sess; s != nil {
			if err := s.Close(); err != nil {
				errs = append(errs, fmt.Errorf("%s: session close: %w", roles[i], err))
			}
		}
	}
	return errors.Join(errs...)
}

// winnerCheckWait is how long the winner check waits for a packet on a
// handed-over socket.
const winnerCheckWait = time.Second

// handoverQuietWindow is how long after Punch returned the handover
// check looks for library calls on the winning socket; goleak, at the end of
// every suite, catches a goroutine that would touch it later.
const handoverQuietWindow = 100 * time.Millisecond

// checkHandover checks the handover of a successful session: the library
// made no call on either winning socket within handoverQuietWindow of
// returning it, and each winning socket receives a packet from the peer
// through a read without deadline (the winner check).
func (r *run) checkHandover() error {
	return r.checkHandoverOpt(!r.skipWinnerCheck)
}

// checkHandoverOpt is checkHandover, with the winner check only when send
// is set.
func (r *run) checkHandoverOpt(send bool) error {
	var views [2]nattest.Conn
	for i := range 2 {
		o := &r.out[i]
		if o.markErr != nil {
			return fmt.Errorf("%s: mark handover %v: %w", roles[i], o.sess.Result().Path.LocalAddr, o.markErr)
		}
		views[i] = o.handed
		if wait := time.Until(o.end.Add(handoverQuietWindow)); wait > 0 {
			time.Sleep(wait)
		}
	}
	for i := range 2 {
		if n := r.sides[i].host.Stats().WritesAfterHandover; n != 0 {
			return fmt.Errorf("%s: %d library calls on the winning socket after Punch returned", roles[i], n)
		}
	}
	for i := range 2 {
		if !send {
			break
		}
		from, to := 1-i, i
		got := make(chan error, 1)
		go func() {
			buf := make([]byte, 2048)
			_, _, err := views[to].ReadFromUDPAddrPort(buf)
			got <- err
		}()
		dst := r.out[from].sess.Result().Path.RemoteAddr
		deadline := time.Now().Add(scaled(winnerCheckWait))
		var err error
		received := false
	send:
		for {
			if _, werr := views[from].WriteToUDPAddrPort([]byte("e2e-handover-check"), dst); werr != nil {
				err = fmt.Errorf("%s: write on the winning socket: %w", roles[from], werr)
				break
			}
			select {
			case rerr := <-got:
				received = true
				if rerr != nil {
					err = fmt.Errorf("%s: read on the winning socket: %w", roles[to], rerr)
				}
				break send
			case <-time.After(50 * time.Millisecond):
			}
			if time.Now().After(deadline) {
				err = fmt.Errorf("%s: no packet on the winning socket within %v", roles[to], scaled(winnerCheckWait))
				break
			}
		}
		if err != nil {
			// The session close closes the socket, which unblocks a reader
			// still waiting.
			_ = r.closeSessions()
			if !received {
				<-got
			}
			return err
		}
	}
	return nil
}
