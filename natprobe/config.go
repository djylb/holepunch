package natprobe

import (
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"slices"

	"github.com/djylb/holepunch/protocol"
)

// Server defaults and bounds.
const (
	defaultPortCount    = 3
	minPortCount        = 2
	maxPortCount        = 8
	defaultExtraSockets = 4
	maxExtraSockets     = 16
	defaultReaders      = 2
	maxReaders          = 8
	defaultSourcePerSec = 512
	defaultSourceBurst  = 1024
	defaultSourceTable  = 4096
	maxSourceTable      = 1 << 20 // the limiter preallocates its table, so the size is bounded
	maxObserverGroups   = 32      // observer id = observer group*8 + port index fits a byte
	portsPerGroup       = 8
	maxFamilyObservers  = 16 // a family's observer ids
)

// ObserverGroup is one set of observer sockets of one address family, bound
// to Bind, and the addresses the clients are sent to for it. A socket bound
// to a specific address replies from it; one bound to the wildcard address
// (0.0.0.0, ::) replies from the address each probe was sent to, on the
// systems that report it (udpsock.EnableDstAddr), and from the address the
// system routes by elsewhere, which on a host with several addresses of the
// family may not be the probed one (ServerStats.WildcardMultiIP).
type ObserverGroup struct {
	Bind netip.Addr
	// Advertise lists the addresses the clients are sent to for these
	// sockets: Bind as seen from outside (≠ Bind behind a 1:1 NAT), and
	// any other address that reaches the same sockets — a second public
	// address routed to this host, the LAN address clients on the server's
	// network use. Each is announced as an observer group of its own, so a
	// client probes every one and its observations count per address. Empty
	// means Bind; a wildcard Bind may leave it empty when sessions get
	// their addresses from Server.ProbeSpecAt.
	Advertise []netip.Addr
	// Slots is how many addresses one session may announce for these
	// sockets: Advertise's, then those Server.ProbeSpecAt adds. 0 means
	// len(Advertise), and at least 1. Every slot is an observer group:
	// Slots × PortCount observer ids.
	Slots int
	// Scope is the kind of address the clients reach these sockets at, which
	// decides what an observation through them is evidence of (a public
	// mapping, or a LAN path only). ScopeAuto takes each address's own,
	// as announced in the session.
	Scope Scope
	// Alt makes the group a second public IP: one listener on BasePort
	// that serves change-IP replies. It needs a specific Bind and has one
	// address.
	Alt bool
}

// Scope is the kind of address an observer group is reached at
// (ObserverGroup.Scope).
type Scope uint8

// Scopes.
const (
	ScopeAuto    Scope = iota // each address's own: public, or private (RFC 1918, ULA, link-local, 100.64/10)
	ScopePublic               // public: observations are evidence of the clients' public mappings
	ScopePrivate              // private: observations are LAN evidence only
)

// ServerConfig configures a Server.
type ServerConfig struct {
	Registry           *Registry       // required; shared, not owned
	Groups             []ObserverGroup // at least one non-alt group; ≤ 32 addresses (slots) in all, ≤ 16 observers and ≤ 1 alt group per family
	BasePort           int             // listeners on BasePort..BasePort+PortCount-1; 0 = ports chosen by the kernel
	PortCount          int             // default 3, 2..8
	NoExtraReply       bool            // disables extra replies; the ack says so
	ExtraSockets       int             // extra-reply pool per group, default 4, 1..16; fixed, never rotated
	ReadersPerListener int             // default 2, 1..8
	SourceRate         Rate            // per source prefix (v4 /32, v6 /64), default {512, 1024}; PerSec < 0 disables it
	SourceTableSize    int             // source limiter LRU size, default 4096, 16..1<<20

	// Listen opens one UDP socket; nil means net.ListenUDP. Its signature is
	// that of nattest.Host.Listen. An injected Listen also
	// turns off the wildcard_multi_ip check, which looks at the host's
	// interfaces.
	//holepunch:callback
	Listen func(network string, laddr netip.AddrPort) (net.PacketConn, error)

	Logger *slog.Logger // optional: recovered panics (at most one a second, never with a stack), stopped listeners, wildcard_multi_ip
}

// normalize applies the defaults to a copy of cfg and validates it.
func normalize(cfg ServerConfig) (ServerConfig, error) {
	if cfg.Registry == nil {
		return cfg, errors.New("natprobe: config: Registry is required")
	}
	if cfg.PortCount == 0 {
		cfg.PortCount = defaultPortCount
	}
	if cfg.ExtraSockets == 0 {
		cfg.ExtraSockets = defaultExtraSockets
	}
	if cfg.ReadersPerListener == 0 {
		cfg.ReadersPerListener = defaultReaders
	}
	if cfg.SourceRate == (Rate{}) {
		cfg.SourceRate = Rate{PerSec: defaultSourcePerSec, Burst: defaultSourceBurst}
	}
	if cfg.SourceRate.PerSec > 0 && cfg.SourceRate.Burst <= 0 {
		cfg.SourceRate.Burst = cfg.SourceRate.PerSec * 2
	}
	if cfg.SourceTableSize == 0 {
		cfg.SourceTableSize = defaultSourceTable
	}
	switch {
	case cfg.PortCount < minPortCount || cfg.PortCount > maxPortCount:
		return cfg, fmt.Errorf("natprobe: config: PortCount %d not in [%d, %d]", cfg.PortCount, minPortCount, maxPortCount)
	case cfg.BasePort < 0 || cfg.BasePort+cfg.PortCount-1 > 65535:
		return cfg, fmt.Errorf("natprobe: config: BasePort %d out of range", cfg.BasePort)
	case cfg.ExtraSockets < 1 || cfg.ExtraSockets > maxExtraSockets:
		return cfg, fmt.Errorf("natprobe: config: ExtraSockets %d not in [1, %d]", cfg.ExtraSockets, maxExtraSockets)
	case cfg.ReadersPerListener < 1 || cfg.ReadersPerListener > maxReaders:
		return cfg, fmt.Errorf("natprobe: config: ReadersPerListener %d not in [1, %d]", cfg.ReadersPerListener, maxReaders)
	case cfg.SourceRate.PerSec == 0:
		return cfg, errors.New("natprobe: config: SourceRate.PerSec is 0")
	case cfg.SourceTableSize < srcShards || cfg.SourceTableSize > maxSourceTable:
		return cfg, fmt.Errorf("natprobe: config: SourceTableSize %d not in [%d, %d]", cfg.SourceTableSize, srcShards, maxSourceTable)
	case len(cfg.Groups) == 0:
		return cfg, errors.New("natprobe: config: no group")
	}
	groups, err := normalizeGroups(cfg.Groups, cfg.PortCount)
	cfg.Groups = groups
	return cfg, err
}

// normalizeGroups checks every group, fills Advertise from a specific Bind
// and Slots from Advertise; the result is a deep copy, so the caller's
// slices are never shared.
func normalizeGroups(in []ObserverGroup, portCount int) ([]ObserverGroup, error) {
	groups := slices.Clone(in)
	var observers, alts [2]int
	var announced []netip.Addr // every Advertise: an address is one observer group
	main, ogs := false, 0
	for i := range groups {
		g := &groups[i]
		g.Advertise = slices.Clone(g.Advertise)
		if !g.Bind.IsValid() || g.Bind.Is4In6() || g.Bind.Zone() != "" || g.Bind.IsMulticast() {
			return nil, fmt.Errorf("natprobe: config: group %d: bad Bind %v", i, g.Bind)
		}
		if g.Scope > ScopePrivate {
			return nil, fmt.Errorf("natprobe: config: group %d: unknown Scope %d", i, g.Scope)
		}
		if len(g.Advertise) == 0 && !g.Bind.IsUnspecified() {
			g.Advertise = []netip.Addr{g.Bind}
		}
		fam := protocol.FamilyOf(g.Bind)
		for k, a := range g.Advertise {
			a = a.Unmap()
			if protocol.FamilyOf(a) != fam || a.IsUnspecified() || a.IsMulticast() || a.Zone() != "" || slices.Contains(announced, a) {
				return nil, fmt.Errorf("natprobe: config: group %d: Advertise %v does not fit Bind %v, or is announced twice", i, a, g.Bind)
			}
			g.Advertise[k] = a
			announced = append(announced, a)
		}
		if g.Slots == 0 {
			g.Slots = max(len(g.Advertise), 1)
		}
		f := fam.Index()
		switch {
		case g.Slots < len(g.Advertise) || g.Slots < 1:
			return nil, fmt.Errorf("natprobe: config: group %d: %d Slots for %d addresses", i, g.Slots, len(g.Advertise))
		case g.Alt && g.Slots != 1:
			return nil, fmt.Errorf("natprobe: config: group %d: an alt group has one address, not %d", i, g.Slots)
		case g.Alt && g.Bind.IsUnspecified():
			return nil, fmt.Errorf("natprobe: config: group %d: an alt group binds a specific address", i)
		case g.Alt:
			alts[f]++
			observers[f]++
		default:
			main = true
			observers[f] += g.Slots * portCount
		}
		if ogs += g.Slots; ogs > maxObserverGroups {
			return nil, fmt.Errorf("natprobe: config: more than %d addresses in all", maxObserverGroups)
		}
		if alts[f] > 1 || observers[f] > maxFamilyObservers {
			return nil, fmt.Errorf("natprobe: config: too many observers or alt groups for %s", fam)
		}
	}
	if !main {
		return nil, errors.New("natprobe: config: no non-alt group")
	}
	return groups, nil
}
