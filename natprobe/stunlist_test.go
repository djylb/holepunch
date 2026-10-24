package natprobe

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/djylb/holepunch/clock"
	"github.com/djylb/holepunch/hostaddr"
)

// fakeLookup answers every name with the addresses set last, or fails while
// they are nil.
type fakeLookup struct {
	mu    sync.Mutex
	addrs []netip.Addr
	calls atomic.Int32
}

func (f *fakeLookup) set(addrs ...string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.addrs = nil
	for _, a := range addrs {
		f.addrs = append(f.addrs, netip.MustParseAddr(a))
	}
}

func (f *fakeLookup) lookup(context.Context, string, string) ([]netip.Addr, error) {
	f.calls.Add(1)
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.addrs == nil {
		return nil, errors.New("injected lookup failure")
	}
	return slices.Clone(f.addrs), nil
}

// runInBackground starts run and returns the function that stops it and
// waits for it to return.
func runInBackground(run func(context.Context)) (stop func()) {
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		run(ctx)
	}()
	return func() {
		cancel()
		<-done
	}
}

// waitArmed waits until the code under test armed its timer, and returns
// how far ahead of now it is due.
func waitArmed(t *testing.T, clk *clock.Fake) time.Duration {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := clk.WaitPending(ctx, 1); err != nil {
		t.Fatal(err)
	}
	next, _ := clk.Next()
	return next.Sub(clk.Now())
}

func TestSTUNListRun(t *testing.T) {
	clk := clock.NewFake(t, time.Unix(1e9, 0))
	var fl fakeLookup
	l := NewSTUNList(STUNListConfig{Servers: []string{"stun.example:3478"}, Lookup: fl.lookup, Clock: clk})
	if l.Addrs() != nil {
		t.Fatal("addresses before the first resolution")
	}
	stop := runInBackground(l.Run)
	defer stop()

	// The first resolution fails: the list stays empty and Run retries
	// after a minute.
	if d := waitArmed(t, clk); d != time.Minute || l.Addrs() != nil {
		t.Fatalf("retry in %v, addrs %v", d, l.Addrs())
	}
	fl.set("198.51.100.1", "2001:db8::1")
	clk.Advance(time.Minute)
	want := []netip.AddrPort{netip.MustParseAddrPort("198.51.100.1:3478"), netip.MustParseAddrPort("[2001:db8::1]:3478")}
	if d := waitArmed(t, clk); d != 6*time.Hour || !slices.Equal(l.Addrs(), want) {
		t.Fatalf("refresh in %v, addrs %v", d, l.Addrs())
	}
	// A failed resolution keeps the addresses found before.
	fl.set()
	clk.Advance(6 * time.Hour)
	if d := waitArmed(t, clk); d != 6*time.Hour || !slices.Equal(l.Addrs(), want) {
		t.Fatalf("after a failure: refresh in %v, addrs %v", d, l.Addrs())
	}
	fl.set("198.51.100.2")
	clk.Advance(6 * time.Hour)
	if d := waitArmed(t, clk); d != 6*time.Hour || !slices.Equal(l.Addrs(), []netip.AddrPort{netip.MustParseAddrPort("198.51.100.2:3478")}) {
		t.Fatalf("after a change: refresh in %v, addrs %v", d, l.Addrs())
	}
	stop()
	if n := fl.calls.Load(); n != 4 {
		t.Fatalf("%d lookups", n)
	}

	// Run after Refresh does not resolve again at once.
	var fl2 fakeLookup
	fl2.set("198.51.100.3")
	l2 := NewSTUNList(STUNListConfig{Servers: []string{"stun.example:3478"}, Lookup: fl2.lookup, Clock: clk, Refresh: time.Hour})
	if err := l2.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	stop2 := runInBackground(l2.Run)
	if d := waitArmed(t, clk); d != time.Hour || fl2.calls.Load() != 1 {
		t.Fatalf("refresh in %v after %d lookups", d, fl2.calls.Load())
	}
	stop2()

	var nilList *STUNList
	if nilList.Addrs() != nil || nilList.Refresh(context.Background()) != nil {
		t.Fatal("nil list")
	}
}

type fakeConn struct {
	net.Conn
	local net.Addr
}

func (c fakeConn) LocalAddr() net.Addr { return c.local }

func TestServerAddrs(t *testing.T) {
	clk := clock.NewFake(t, time.Unix(1e9, 0))
	var fl fakeLookup
	ifaces := []hostaddr.Addr{
		{Prefix: netip.MustParsePrefix("203.0.113.5/24"), Up: true, Kind: hostaddr.Public},
		{Prefix: netip.MustParsePrefix("2001:db8::5/64"), Up: true, Kind: hostaddr.Public},
		{Prefix: netip.MustParsePrefix("203.0.113.6/24"), Up: false, Kind: hostaddr.Public},
		{Prefix: netip.MustParsePrefix("192.168.1.5/24"), Up: true, Kind: hostaddr.LAN},
		{Prefix: netip.MustParsePrefix("100.100.1.5/32"), Up: true, Kind: hostaddr.Overlay},
	}
	var ifErr error
	a := NewServerAddrs(ServerAddrsConfig{
		Public:     []netip.Addr{netip.MustParseAddr("198.51.100.9"), netip.MustParseAddr("::ffff:198.51.100.9"), netip.IPv4Unspecified()},
		Names:      []string{"ddns.example"},
		HostPublic: true,
		Lookup:     fl.lookup,
		Interfaces: func() ([]hostaddr.Addr, error) { return ifaces, ifErr },
		Clock:      clk,
	})
	pub := netip.MustParseAddr("198.51.100.9")
	if got := a.Addrs(); !slices.Equal(got, []netip.Addr{pub}) {
		t.Fatalf("before a refresh %v", got)
	}
	fl.set("198.51.100.20", "203.0.113.5")
	stop := runInBackground(a.Run)
	defer stop()
	if d := waitArmed(t, clk); d != 5*time.Minute {
		t.Fatalf("refresh in %v", d)
	}
	want := []netip.Addr{pub, netip.MustParseAddr("198.51.100.20"), netip.MustParseAddr("203.0.113.5"), netip.MustParseAddr("2001:db8::5")}
	if got := a.Addrs(); !slices.Equal(got, want) {
		t.Fatalf("addrs %v, want %v", got, want)
	}
	// The control connection's local address comes first, once.
	ctl := fakeConn{local: &net.TCPAddr{IP: net.ParseIP("203.0.113.5"), Port: 4343}}
	if got := a.For(ctl); !slices.Equal(got, append([]netip.Addr{netip.MustParseAddr("203.0.113.5"), pub, netip.MustParseAddr("198.51.100.20")}, netip.MustParseAddr("2001:db8::5"))) {
		t.Fatalf("for the control conn %v", got)
	}
	wild := fakeConn{local: &net.TCPAddr{IP: net.IPv4zero, Port: 4343}}
	if got := a.For(wild); !slices.Equal(got, want) {
		t.Fatalf("for a wildcard control conn %v", got)
	}
	// Failed reads keep the previous addresses.
	fl.set()
	ifErr = errors.New("injected interface failure")
	clk.Advance(5 * time.Minute)
	waitArmed(t, clk)
	if got := a.Addrs(); !slices.Equal(got, want) {
		t.Fatalf("after failures %v", got)
	}
	stop()

	var nilAddrs *ServerAddrs
	if got := nilAddrs.For(ctl); !slices.Equal(got, []netip.Addr{netip.MustParseAddr("203.0.113.5")}) || nilAddrs.Addrs() != nil {
		t.Fatalf("nil: %v", got)
	}
	if err := a.Refresh(context.Background()); err == nil {
		t.Fatal("the failures were not reported")
	}
	// Nothing to refresh: Run returns at once.
	NewServerAddrs(ServerAddrsConfig{Public: []netip.Addr{pub}}).Run(context.Background())
}

func TestSpecSource(t *testing.T) {
	s := startServer(t, ServerConfig{Groups: []ObserverGroup{{Bind: netip.IPv4Unspecified(), Slots: 2}}})
	var fl fakeLookup
	fl.set("198.51.100.1")
	stunList := NewSTUNList(STUNListConfig{Servers: []string{"stun.example:3478"}, Lookup: fl.lookup})
	if err := stunList.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	pub := netip.MustParseAddr("203.0.113.1")
	src := SpecSource{Server: s, STUN: stunList, Addrs: NewServerAddrs(ServerAddrsConfig{Public: []netip.Addr{pub}})}
	spec := src.Spec()
	if len(spec.Observers) != 3 || spec.Observers[0].Addr.Addr() != pub || !slices.Equal(spec.STUN, stunList.Addrs()) {
		t.Fatalf("spec %+v", spec)
	}
	ctl := fakeConn{local: &net.TCPAddr{IP: net.ParseIP("192.0.2.7"), Port: 4343}}
	spec = src.SpecFor(ctl)
	if len(spec.Observers) != 6 || spec.Observers[0].Addr.Addr() != netip.MustParseAddr("192.0.2.7") {
		t.Fatalf("spec for the control conn %+v", spec.Observers)
	}
	if spec := (SpecSource{Server: s}).Spec(); len(spec.Observers) != 0 || spec.STUN != nil {
		t.Fatalf("no addresses: %+v", spec)
	}
}
