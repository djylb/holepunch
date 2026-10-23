package broker

import (
	"cmp"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"fmt"
	"maps"
	"slices"
	"sync"
	"time"

	"github.com/djylb/holepunch/coord"
	"github.com/djylb/holepunch/standalone/internal/life"
	"github.com/djylb/holepunch/standalone/proto"
)

// DefaultMaxHosts is the registry bound used when Config.MaxHosts is zero.
const DefaultMaxHosts = 65536

// Errors of the broker. Errors of the coordinator (coord.ErrBusy, …) are
// returned as they are.
var (
	ErrClosed          = errors.New("broker: closed")
	ErrInvalidRequest  = errors.New("broker: invalid request")
	ErrHostNotFound    = errors.New("broker: host not found")
	ErrHostExists      = errors.New("broker: host ID held by a live registration")
	ErrRegistryFull    = errors.New("broker: host registry full")
	ErrRefused         = errors.New("broker: open refused")
	ErrSessionNotFound = errors.New("broker: session not found")
)

// Config configures a Broker.
type Config struct {
	// Coord configures the coordinator the broker creates and owns. Its
	// OnResult still receives every Result, after the broker has forgotten
	// the session.
	Coord coord.Config
	// Authorize decides whether a dialer may open a session with a host and
	// returns the session's AccessPolicy; an error refuses the open
	// (ErrRefused). nil allows every open with an empty policy. It is called
	// outside every lock, inside a recover boundary: a panic refuses the
	// open.
	Authorize func(OpenRequest, HostInfo) (proto.AccessPolicy, error) //holepunch:callback
	// MaxHosts bounds the registry; 0 means DefaultMaxHosts.
	MaxHosts int
}

// Broker is the host registry and matchmaker. Create it with New.
type Broker struct {
	coord     *coord.Coordinator
	authorize func(OpenRequest, HostInfo) (proto.AccessPolicy, error)
	maxHosts  int
	now       func() time.Time

	mu       sync.Mutex
	closed   bool
	hosts    map[string]*Host
	sessions map[string]*Session

	closeOnce sync.Once
	closeErr  error
}

// New creates the broker and its coordinator.
func New(cfg Config) (*Broker, error) {
	if cfg.MaxHosts < 0 {
		return nil, fmt.Errorf("%w: negative MaxHosts", ErrInvalidRequest)
	}
	b := &Broker{
		authorize: cfg.Authorize,
		maxHosts:  cmp.Or(cfg.MaxHosts, DefaultMaxHosts),
		now:       time.Now,
		hosts:     map[string]*Host{},
		sessions:  map[string]*Session{},
	}
	if cfg.Coord.Clock != nil {
		b.now = cfg.Coord.Clock.Now
	}
	onResult := cfg.Coord.OnResult
	cfg.Coord.OnResult = func(r coord.Result) {
		b.forget(r.SessionID)
		if onResult != nil {
			_ = life.Safe("broker.OnResult", func() { onResult(r) })
		}
	}
	c, err := coord.New(cfg.Coord)
	if err != nil {
		return nil, err
	}
	b.coord = c
	return b, nil
}

// Coordinator returns the coordinator that runs the broker's sessions, for
// its Stats, Memory and Lookup.
func (b *Broker) Coordinator() *coord.Coordinator { return b.coord }

// Close unregisters every host — asking each Signal to Revoke its link —
// and closes the coordinator, which ends every session with server_shutdown
// within its 3 s bound. It returns the coordinator's error. It is idempotent
// and safe for concurrent use; Register and Open return ErrClosed afterwards.
func (b *Broker) Close() error {
	b.closeOnce.Do(func() {
		b.mu.Lock()
		b.closed = true
		hosts := slices.Collect(maps.Values(b.hosts))
		clear(b.hosts)
		for _, h := range hosts {
			h.gone = true
		}
		b.mu.Unlock()
		for _, h := range hosts {
			h.revoke()
		}
		b.closeErr = b.coord.Close()
	})
	return b.closeErr
}

// Snapshot is a copy of the broker's state.
type Snapshot struct {
	Hosts    []HostInfo // sorted by ID
	Sessions int        // live sessions the broker created
	Pending  int        // of those, not joined by their host yet
}

// Snapshot returns a copy of the broker's state.
func (b *Broker) Snapshot() Snapshot {
	b.mu.Lock()
	snap := Snapshot{Hosts: make([]HostInfo, 0, len(b.hosts)), Sessions: len(b.sessions)}
	for _, h := range b.hosts {
		snap.Hosts = append(snap.Hosts, h.infoLocked())
	}
	for _, s := range b.sessions {
		if !s.joined {
			snap.Pending++
		}
	}
	b.mu.Unlock()
	slices.SortFunc(snap.Hosts, func(x, y HostInfo) int { return cmp.Compare(x.HostID, y.HostID) })
	return snap
}

// forget drops a session the coordinator has finished.
func (b *Broker) forget(id string) {
	b.mu.Lock()
	if s := b.sessions[id]; s != nil {
		delete(b.sessions, id)
		delete(s.host.sessions, id)
	}
	b.mu.Unlock()
}

// secret is a one-time secret: credentials and tickets.
type secret [sha256.Size]byte

// newSecret draws a random secret and returns its text and digest.
func newSecret() (string, secret) {
	text := rand.Text()
	return text, sha256.Sum256([]byte(text))
}

// matches compares the digest of given with s in constant time; comparing
// digests keeps even the length of the secret out of the timing.
func (s secret) matches(given string) bool {
	g := sha256.Sum256([]byte(given))
	return subtle.ConstantTimeCompare(s[:], g[:]) == 1
}
