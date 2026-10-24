package quicpath_test

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/quic-go/quic-go"

	"github.com/djylb/holepunch"
	"github.com/djylb/holepunch/coord"
	"github.com/djylb/holepunch/internal/goroutines"
	"github.com/djylb/holepunch/natprobe"
	"github.com/djylb/holepunch/nattest"
	"github.com/djylb/holepunch/protocol"
	"github.com/djylb/holepunch/quicpath"
)

func TestMain(m *testing.M) { goroutines.VerifyTestMain(m) }

// alpn is the application protocol of the tests.
const alpn = "quicpath-test"

// world is a simulated Internet with a holepunch server (natprobe and a
// coordinator) on a public host. The test's cleanup closes everything.
type world struct {
	n      *nattest.Network
	server *nattest.Host
	co     *coord.Coordinator
}

func newWorld(t *testing.T) *world {
	t.Helper()
	w := &world{n: nattest.NewNetwork(nattest.WithSeed(1))}
	t.Cleanup(func() { _ = w.n.Close() })
	w.server = w.n.PublicHost(netip.IPv4Unspecified())
	reg := natprobe.NewRegistry(natprobe.RegistryConfig{})
	probe, err := natprobe.NewServer(natprobe.ServerConfig{
		Registry: reg, Groups: []natprobe.ObserverGroup{{Bind: w.server.Addrs()[0]}},
		Listen: w.server.Listen, SourceRate: natprobe.Rate{PerSec: -1},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = probe.Close() })
	if err := probe.Start(); err != nil {
		t.Fatal(err)
	}
	w.co, err = coord.New(coord.Config{Registry: reg, DefaultProbe: probe.ProbeSpec(), Timeouts: protocol.Timeouts{
		ProbeTimeoutMs: 600, SummaryWaitMs: 3000, GoWaitMs: 1500, HandshakeTimeoutMs: 4000,
		HandoverTimeoutMs: 1500, TransportTimeoutMs: 3000, MaxRounds: 3,
	}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = w.co.Close() })
	return w
}

// side is one client of a punch.
type side struct {
	host *nattest.Host
	data []byte // Options.TransportData
}

// punch runs one session between two clients, the initiator first, with
// maxPaths confirmed paths at most, and returns their sessions; the
// test's cleanup closes them.
func (w *world) punch(t *testing.T, sides [2]side, maxPaths int) [2]*holepunch.Session {
	t.Helper()
	cs, err := w.co.NewSession(coord.SessionOptions{})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	var (
		wg   sync.WaitGroup
		out  [2]*holepunch.Session
		errs [2]error
	)
	for i, role := range []protocol.Role{protocol.RoleInitiator, protocol.RoleResponder} {
		clientEnd, serverEnd := w.n.Pipe(nattest.PipeConfig{A: sides[i].host, B: w.server})
		t.Cleanup(func() { _ = clientEnd.Close() })
		if err := cs.Attach(role, serverEnd, coord.AttachOptions{Security: protocol.ControlSecurityInsecureForTesting}); err != nil {
			t.Fatal(err)
		}
		wg.Go(func() {
			out[i], errs[i] = holepunch.Punch(ctx, clientEnd, holepunch.Options{
				ControlSecurity: protocol.ControlSecurityInsecureForTesting,
				Network:         sides[i].host,
				TransportMode:   "quic",
				TransportData:   sides[i].data,
				ExcludeOverlay:  true,
				MaxPaths:        maxPaths,
			})
		})
	}
	wg.Wait()
	for _, s := range out {
		if s != nil {
			t.Cleanup(func() { _ = s.Close() })
		}
	}
	if err := errors.Join(errs[:]...); err != nil {
		t.Fatal(err)
	}
	return out
}

// pinned is a punched session between two hosts behind full-cone NATs,
// each side announcing its identity.
type pinned struct {
	w     *world
	hosts [2]*nattest.Host
	ids   [2]*quicpath.Identity
	sess  [2]*holepunch.Session
}

func newPinned(t *testing.T) *pinned {
	t.Helper()
	p := &pinned{w: newWorld(t)}
	var sides [2]side
	for i := range 2 {
		p.hosts[i] = p.w.n.NAT(nattest.FullCone()).Host()
		p.ids[i] = identity(t)
		sides[i] = side{host: p.hosts[i], data: p.ids[i].TransportData()}
	}
	p.sess = p.w.punch(t, sides, 1)
	return p
}

func identity(t *testing.T) *quicpath.Identity {
	t.Helper()
	id, err := quicpath.NewIdentity(alpn)
	if err != nil {
		t.Fatal(err)
	}
	return id
}

// tlsConfig is side i's configuration from identity id.
func (p *pinned) tlsConfig(t *testing.T, i int, id *quicpath.Identity) *tls.Config {
	t.Helper()
	conf, err := id.TLSConfig(p.sess[i].Result())
	if err != nil {
		t.Fatal(err)
	}
	return conf
}

type connected struct {
	conn *quicpath.Conn
	err  error
}

// connect dials from the initiator and accepts on the responder at once,
// with the given identities and QUIC configuration, and returns both
// outcomes; the test's cleanup closes the Conns.
func (p *pinned) connect(t *testing.T, ids [2]*quicpath.Identity, conf *quic.Config) (dial, acc connected) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	done := make(chan connected, 1)
	go func() {
		c, err := quicpath.Accept(ctx, p.sess[1], p.tlsConfig(t, 1, ids[1]), conf)
		done <- connected{c, err}
	}()
	c, err := quicpath.Dial(ctx, p.sess[0], p.tlsConfig(t, 0, ids[0]), conf)
	dial, acc = connected{c, err}, <-done
	for _, o := range []connected{dial, acc} {
		if o.conn != nil {
			t.Cleanup(func() { _ = o.conn.Close() })
		}
	}
	return dial, acc
}

// echo serves one stream of c: it copies what it reads back until EOF.
func echo(c *quicpath.Conn) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	st, err := c.QUIC().AcceptStream(ctx)
	if err != nil {
		return err
	}
	_, err = io.Copy(st, st)
	if cerr := st.Close(); err == nil {
		err = cerr
	}
	return err
}

// roundTrip sends msg over a new stream of c and wants it echoed.
func roundTrip(t *testing.T, c *quicpath.Conn, msg string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	st, err := c.QUIC().OpenStreamSync(ctx)
	if err != nil {
		t.Fatal(err)
	}
	_ = st.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := st.Write([]byte(msg)); err != nil {
		t.Fatal(err)
	}
	_ = st.Close()
	got, err := io.ReadAll(st)
	if err != nil || string(got) != msg {
		t.Fatalf("echo %q, %v; want %q", got, err, msg)
	}
}

// waitDone waits for c to die and returns its Err.
func waitDone(t *testing.T, c *quicpath.Conn, within time.Duration) error {
	t.Helper()
	select {
	case <-c.Done():
		return c.Err()
	case <-time.After(within):
		t.Fatalf("pipe on %v still alive after %v", c.Path().RemoteAddr, within)
		return nil
	}
}
