package e2e

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"os"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/djylb/holepunch/controlwire"
	"github.com/djylb/holepunch/nattest"
	"github.com/djylb/holepunch/protocol"
)

// direction of a control frame.
type direction uint8

const (
	toClient direction = iota // written by the coordinator
	toServer                  // written by the client
)

func (d direction) String() string {
	if d == toClient {
		return "s2c"
	}
	return "c2s"
}

// frameEvent is one control frame that crossed a tap.
type frameEvent struct {
	Dir  direction
	Type controlwire.Type
	At   time.Time
	Msg  protocol.Message // decoded and validated; nil when it is not
	Size int
}

// maxTapEvents bounds the frames a tap keeps; the frames past it are only
// counted (tap.dropped), and a run whose tap dropped any fails its checks.
const maxTapEvents = 2048

// tap is the coordinator's end of one control link, interposed on the
// server end of a nattest pipe. It forwards every frame unchanged and, frame
// by frame, decodes what crosses it; a test can hold the next frame of a
// type in either direction while it injects a fault at that protocol point
// (and then deliver or drop it), write raw bytes between server frames
// (malformed frames) and stop reading the client (back-pressure). The
// coordinator owns it after Attach and closes it; Close closes the pipe end
// and ends every hold.
type tap struct {
	pipe *nattest.PipeConn
	// light skips decoding and logs only the milestones (load tests).
	light  bool
	frames atomic.Int64

	wmu  sync.Mutex // one server frame at a time; inject takes it too
	wbuf []byte

	// The coordinator's reader goroutine alone touches the read side.
	rbuf  []byte // read from the pipe, not yet returned
	ready int    // leading bytes of rbuf that may be returned
	rerr  error  // the pipe's read error, returned once rbuf is drained

	mu       sync.Mutex
	events   []frameEvent
	dropped  int // frames not kept beyond maxTapEvents
	holds    []*hold
	watchers []*watcher
	subs     []*watcher    // persistent: every matching frame
	gate     chan struct{} // non-nil: reads blocked until the tap closes
	wdl      time.Time

	closed    chan struct{}
	closeOnce sync.Once
}

func newTap(pipe *nattest.PipeConn) *tap {
	return &tap{pipe: pipe, closed: make(chan struct{})}
}

// hold holds the next frame of a direction and type (and predicate) at the
// tap.
type hold struct {
	dir       direction
	typ       controlwire.Type
	pred      func(protocol.Message) bool
	reached   chan struct{}
	reachOnce sync.Once
	rel       chan struct{}
	relOnce   sync.Once
	drop      atomic.Bool
}

// Reached is closed when a matching frame arrived and is held.
func (h *hold) Reached() <-chan struct{} { return h.reached }

// Release lets the held frame go on; idempotent, and it may come first.
func (h *hold) Release() { h.relOnce.Do(func() { close(h.rel) }) }

// Drop discards the held frame, as if the sender had never written it.
func (h *hold) Drop() {
	h.drop.Store(true)
	h.Release()
}

// holdNext arms a hold on the next frame of direction d and type typ for
// which pred (nil: any) is true.
func (t *tap) holdNext(d direction, typ controlwire.Type, pred func(protocol.Message) bool) *hold {
	h := &hold{dir: d, typ: typ, pred: pred, reached: make(chan struct{}), rel: make(chan struct{})}
	t.mu.Lock()
	t.holds = append(t.holds, h)
	t.mu.Unlock()
	return h
}

// watcher is a one-shot frame trigger (ch) or a subscription (fn).
type watcher struct {
	dir  direction
	typ  controlwire.Type
	pred func(protocol.Message) bool
	ch   chan frameEvent
	fn   func(frameEvent)
}

// when returns a channel that receives the first frame of the direction and
// type for which pred (nil: any) is true, once it crossed the tap.
func (t *tap) when(d direction, typ controlwire.Type, pred func(protocol.Message) bool) <-chan frameEvent {
	w := &watcher{dir: d, typ: typ, pred: pred, ch: make(chan frameEvent, 1)}
	t.mu.Lock()
	t.watchers = append(t.watchers, w)
	t.mu.Unlock()
	return w.ch
}

// subscribe calls fn with every frame of the direction and type that
// crosses the tap from now on, as it is forwarded. fn runs on the goroutine
// that moves the frame and must not block or call into the tap.
func (t *tap) subscribe(d direction, typ controlwire.Type, fn func(frameEvent)) {
	w := &watcher{dir: d, typ: typ, fn: fn}
	t.mu.Lock()
	t.subs = append(t.subs, w)
	t.mu.Unlock()
}

// stopReading makes the coordinator's reads block until the tap closes:
// the client's writes then fill the pipe's buffer and block too.
func (t *tap) stopReading() {
	t.mu.Lock()
	if t.gate == nil {
		t.gate = make(chan struct{})
	}
	t.mu.Unlock()
}

// inject writes raw bytes to the client between two server frames.
func (t *tap) inject(b []byte) error {
	t.wmu.Lock()
	defer t.wmu.Unlock()
	_, err := t.pipe.Write(b)
	return err
}

// log returns a copy of the frames seen so far.
func (t *tap) log() []frameEvent {
	t.mu.Lock()
	defer t.mu.Unlock()
	return append([]frameEvent(nil), t.events...)
}

// logComplete returns nil when the log holds every frame it should, or an
// error naming how many it dropped: the assertions on the log would then
// miss frames.
func (t *tap) logComplete() error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.dropped == 0 {
		return nil
	}
	return fmt.Errorf("control log full: %d frames kept, %d dropped", len(t.events), t.dropped)
}

// frameLen returns the length of the first complete frame of b, or 0.
func frameLen(b []byte) int {
	if len(b) < controlwire.HeaderSize {
		return 0
	}
	n := controlwire.HeaderSize + int(binary.BigEndian.Uint32(b[4:8]))
	if len(b) < n {
		return 0
	}
	return n
}

// decode decodes a frame unless the tap is light.
func (t *tap) decode(raw []byte) (controlwire.Type, protocol.Message) {
	if t.light {
		return controlwire.Type(raw[3]), nil
	}
	return decodeFrame(raw)
}

// decodeFrame decodes one complete frame; a frame that does not decode
// yields nil.
func decodeFrame(raw []byte) (controlwire.Type, protocol.Message) {
	typ := controlwire.Type(raw[3])
	m, err := protocol.Decode(controlwire.Frame{Type: typ, Payload: raw[controlwire.HeaderSize:]})
	if err != nil {
		return typ, nil
	}
	return typ, m
}

// note records a frame that crossed the tap and fires the watchers it
// matches.
func (t *tap) note(d direction, typ controlwire.Type, m protocol.Message, size int) {
	ev := frameEvent{Dir: d, Type: typ, At: time.Now(), Msg: m, Size: size}
	t.frames.Add(1)
	t.mu.Lock()
	if !t.light || lightKept(typ) {
		if len(t.events) < maxTapEvents {
			t.events = append(t.events, ev)
		} else {
			t.dropped++
		}
	}
	ws := t.watchers[:0:0]
	for _, w := range t.watchers {
		if w.dir == d && w.typ == typ && (w.pred == nil || w.pred(m)) {
			w.ch <- ev
			continue
		}
		ws = append(ws, w)
	}
	t.watchers = ws
	var fns []func(frameEvent)
	for _, w := range t.subs {
		if w.dir == d && w.typ == typ {
			fns = append(fns, w.fn)
		}
	}
	t.mu.Unlock()
	for _, fn := range fns {
		fn(ev)
	}
}

// lightKept reports whether a light tap logs a frame type: the session's
// milestones, not pings, pongs or progress.
func lightKept(typ controlwire.Type) bool {
	switch typ {
	case controlwire.TypePing, controlwire.TypePong, controlwire.TypeProgress, controlwire.TypeAssist:
		return false
	}
	return true
}

// takeHold returns the armed hold a frame matches, removing it.
func (t *tap) takeHold(d direction, typ controlwire.Type, m protocol.Message) *hold {
	t.mu.Lock()
	defer t.mu.Unlock()
	for i, h := range t.holds {
		if h.dir == d && h.typ == typ && (h.pred == nil || h.pred(m)) {
			t.holds = append(t.holds[:i], t.holds[i+1:]...)
			return h
		}
	}
	return nil
}

// waitHold blocks a held frame until it is released or the tap closes;
// a server frame also gives up at the coordinator's write deadline. It
// reports whether to deliver the frame.
func (t *tap) waitHold(h *hold) (bool, error) {
	h.reachOnce.Do(func() { close(h.reached) })
	var expire <-chan time.Time
	if h.dir == toClient {
		t.mu.Lock()
		dl := t.wdl
		t.mu.Unlock()
		if !dl.IsZero() {
			tm := time.NewTimer(time.Until(dl))
			defer tm.Stop()
			expire = tm.C
		}
	}
	select {
	case <-h.rel:
		return !h.drop.Load(), nil
	case <-t.closed:
		return false, net.ErrClosed
	case <-expire:
		return false, os.ErrDeadlineExceeded
	}
}

// Write forwards the coordinator's bytes frame by frame.
func (t *tap) Write(b []byte) (int, error) {
	t.wmu.Lock()
	defer t.wmu.Unlock()
	t.wbuf = append(t.wbuf, b...)
	for {
		n := frameLen(t.wbuf)
		if n == 0 {
			return len(b), nil
		}
		frame := append([]byte(nil), t.wbuf[:n]...)
		t.wbuf = append(t.wbuf[:0], t.wbuf[n:]...)
		typ, m := t.decode(frame)
		if h := t.takeHold(toClient, typ, m); h != nil {
			t.wmu.Unlock()
			deliver, err := t.waitHold(h)
			t.wmu.Lock()
			if err != nil {
				t.wbuf = t.wbuf[:0]
				return 0, err
			}
			if !deliver {
				continue
			}
		}
		if _, err := t.pipe.Write(frame); err != nil {
			t.wbuf = t.wbuf[:0]
			return 0, err
		}
		t.note(toClient, typ, m, n)
	}
}

// Read returns the client's bytes to the coordinator frame by frame, so
// that a frame can be held or dropped before the coordinator sees any of
// it; a frame is released whole.
func (t *tap) Read(b []byte) (int, error) {
	for t.ready == 0 {
		if fl := frameLen(t.rbuf); fl > 0 {
			if err := t.admit(fl); err != nil {
				return 0, err
			}
			continue
		}
		if t.rerr != nil {
			if t.rerr == io.EOF && len(t.rbuf) > 0 {
				// a partial frame before EOF goes to the coordinator as is
				t.ready = len(t.rbuf)
				break
			}
			return 0, t.rerr
		}
		t.mu.Lock()
		gate := t.gate
		t.mu.Unlock()
		if gate != nil {
			select {
			case <-gate:
			case <-t.closed:
				return 0, net.ErrClosed
			}
		}
		buf := make([]byte, 4096)
		n, err := t.pipe.Read(buf)
		t.rbuf = append(t.rbuf, buf[:n]...)
		if err != nil {
			t.rerr = err
		}
	}
	n := copy(b, t.rbuf[:t.ready])
	t.rbuf = append(t.rbuf[:0], t.rbuf[n:]...)
	t.ready -= n
	return n, nil
}

// admit decides about the complete client frame at the start of rbuf (after
// the ready bytes, of which there are none): it is noted, held if a hold
// matches, then made readable or dropped.
func (t *tap) admit(fl int) error {
	frame := t.rbuf[:fl]
	typ, m := t.decode(frame)
	deliver := true
	if h := t.takeHold(toServer, typ, m); h != nil {
		var err error
		if deliver, err = t.waitHold(h); err != nil {
			return err
		}
	}
	if !deliver {
		t.rbuf = append(t.rbuf[:0], t.rbuf[fl:]...)
		return nil
	}
	t.note(toServer, typ, m, fl)
	t.ready = fl
	return nil
}

// Close closes the pipe end and ends every hold and blocked read.
func (t *tap) Close() error {
	t.closeOnce.Do(func() { close(t.closed) })
	return t.pipe.Close()
}

func (t *tap) LocalAddr() net.Addr  { return t.pipe.LocalAddr() }
func (t *tap) RemoteAddr() net.Addr { return t.pipe.RemoteAddr() }

func (t *tap) SetDeadline(d time.Time) error {
	t.mu.Lock()
	t.wdl = d
	t.mu.Unlock()
	return t.pipe.SetDeadline(d)
}

func (t *tap) SetReadDeadline(d time.Time) error { return t.pipe.SetReadDeadline(d) }

func (t *tap) SetWriteDeadline(d time.Time) error {
	t.mu.Lock()
	t.wdl = d
	t.mu.Unlock()
	return t.pipe.SetWriteDeadline(d)
}

// ctlSpy is the client's end of a control link: it forwards everything to
// the pipe and records what the library leaves behind, for the ownership
// check: no read in flight and both deadlines cleared once AttachSession has
// returned.
type ctlSpy struct {
	*nattest.PipeConn
	inflight atomic.Int32
	mu       sync.Mutex
	rdl, wdl time.Time
}

func (s *ctlSpy) Read(b []byte) (int, error) {
	s.inflight.Add(1)
	defer s.inflight.Add(-1)
	return s.PipeConn.Read(b)
}

func (s *ctlSpy) SetDeadline(t time.Time) error {
	s.mu.Lock()
	s.rdl, s.wdl = t, t
	s.mu.Unlock()
	return s.PipeConn.SetDeadline(t)
}

func (s *ctlSpy) SetReadDeadline(t time.Time) error {
	s.mu.Lock()
	s.rdl = t
	s.mu.Unlock()
	return s.PipeConn.SetReadDeadline(t)
}

func (s *ctlSpy) SetWriteDeadline(t time.Time) error {
	s.mu.Lock()
	s.wdl = t
	s.mu.Unlock()
	return s.PipeConn.SetWriteDeadline(t)
}

// returned reports whether the library gave the connection back clean.
func (s *ctlSpy) returned() (inflight int, rdl, wdl time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return int(s.inflight.Load()), s.rdl, s.wdl
}

// TestTapRead checks the coordinator's side of a tap: a held client frame
// reaches it only once released, a dropped one never, and the bytes of a
// frame cut short by the client's close arrive as they are, then io.EOF.
func TestTapRead(t *testing.T) {
	n := nattest.NewNetwork(nattest.WithEventLog(0))
	defer func() { _ = n.Close() }()
	cli, srv := n.Pipe(nattest.PipeConfig{})
	tp := newTap(srv)
	defer func() { _ = tp.Close() }()
	frame := func(typ controlwire.Type, payload string) []byte {
		b := []byte{'h', 'p', controlwire.Version, byte(typ), 0, 0, 0, 0}
		binary.BigEndian.PutUint32(b[4:], uint32(len(payload)))
		return append(b, payload...)
	}
	held := tp.holdNext(toServer, controlwire.TypeProgress, nil)
	dropped := tp.holdNext(toServer, controlwire.TypePong, nil)
	first, second, third := frame(controlwire.TypeProgress, "one"), frame(controlwire.TypePong, "two"), frame(controlwire.TypeRoundResult, "three")
	tail := frame(controlwire.TypePunchResult, "cut short")[:10]
	go func() {
		<-held.Reached()
		held.Release()
		<-dropped.Reached()
		dropped.Drop()
	}()
	var stream []byte
	for _, b := range [][]byte{first, second, third, tail} {
		stream = append(stream, b...)
	}
	if _, err := cli.Write(stream); err != nil {
		t.Fatal(err)
	}
	if err := cli.Close(); err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(tp)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if want := slices.Concat(first, third, tail); !bytes.Equal(got, want) {
		t.Fatalf("coordinator read %q, want %q", got, want)
	}
	if err := tp.logComplete(); err != nil {
		t.Fatal(err)
	}
	if l := tp.log(); len(l) != 2 || l[0].Type != controlwire.TypeProgress || l[1].Type != controlwire.TypeRoundResult {
		t.Fatalf("log %+v, want the delivered progress and round_result", l)
	}
}

// TestTapLogOverflow checks that a tap whose log is full says so instead of
// silently losing the later frames.
func TestTapLogOverflow(t *testing.T) {
	tp := &tap{closed: make(chan struct{})}
	for range maxTapEvents {
		tp.note(toServer, controlwire.TypeProgress, nil, controlwire.HeaderSize)
	}
	if err := tp.logComplete(); err != nil {
		t.Fatalf("full log: %v", err)
	}
	tp.note(toServer, controlwire.TypePunchResult, nil, controlwire.HeaderSize)
	if err := tp.logComplete(); err == nil {
		t.Fatal("a frame past the log's bound went unreported")
	}
}
