package natprobe

import (
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"time"

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
	maxGroups           = 32      // observer id = group*8 + port index fits a byte
	portsPerGroup       = 8
	maxFamilyObservers  = 16 // a family's listeners
	maxSpecObservers    = 16 // ProbeSpec.observers in all (protocol)
)

// ObserverGroup describes one server IP of one address family, bound
// explicitly so that replies leave from the probed address (no
// IP_PKTINFO, hence no golang.org/x/net).
type ObserverGroup struct {
	Bind      netip.Addr // local bind address; unspecified (0.0.0.0, ::) only on single-IP hosts
	Advertise netip.Addr // the address announced to clients (≠ Bind behind a 1:1 NAT); zero means Bind, which a wildcard Bind does not allow
	Alt       bool       // a second public IP: one listener on BasePort that serves change-IP replies
}

// ServerConfig configures a Server.
type ServerConfig struct {
	Registry           *Registry       // required; shared, not owned
	Groups             []ObserverGroup // at least one non-alt group; ≤ 32 groups, ≤ 16 observers and ≤ 1 alt group per family
	BasePort           int             // listeners on BasePort..BasePort+PortCount-1; 0 = ports chosen by the kernel
	PortCount          int             // default 3, 2..8
	NoExtraReply       bool            // disables extra replies; the ack says so
	ExtraSockets       int             // extra-reply pool per group, default 4, 1..16; fixed, never rotated
	ReadersPerListener int             // default 2, 1..8
	SourceRate         Rate            // per source prefix (v4 /32, v6 /64), default {512, 1024}; PerSec < 0 disables it
	SourceTableSize    int             // source limiter LRU size, default 4096, 16..1<<20
	SweepInterval      time.Duration   // 0: never, the coordinator sweeps the Registry; 10 s for a natprobe on its own

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
	case cfg.SweepInterval < 0:
		return cfg, errors.New("natprobe: config: negative SweepInterval")
	case len(cfg.Groups) == 0 || len(cfg.Groups) > maxGroups:
		return cfg, fmt.Errorf("natprobe: config: %d groups, want 1..%d", len(cfg.Groups), maxGroups)
	}
	groups, err := normalizeGroups(cfg.Groups, cfg.PortCount)
	cfg.Groups = groups
	return cfg, err
}

// normalizeGroups checks every group and fills Advertise from Bind; the
// result is a copy, so the caller's slice is never shared.
func normalizeGroups(in []ObserverGroup, portCount int) ([]ObserverGroup, error) {
	groups := append([]ObserverGroup(nil), in...)
	var observers, alts [2]int
	main := false
	for i := range groups {
		g := &groups[i]
		if !g.Bind.IsValid() || g.Bind.Is4In6() || g.Bind.Zone() != "" || g.Bind.IsMulticast() {
			return nil, fmt.Errorf("natprobe: config: group %d: bad Bind %v", i, g.Bind)
		}
		if !g.Advertise.IsValid() {
			if g.Bind.IsUnspecified() {
				return nil, fmt.Errorf("natprobe: config: group %d: a wildcard Bind needs Advertise", i)
			}
			g.Advertise = g.Bind
		}
		g.Advertise = g.Advertise.Unmap()
		fam := protocol.FamilyOf(g.Bind)
		if protocol.FamilyOf(g.Advertise) != fam || g.Advertise.IsUnspecified() || g.Advertise.IsMulticast() || g.Advertise.Zone() != "" {
			return nil, fmt.Errorf("natprobe: config: group %d: Advertise %v does not fit Bind %v", i, g.Advertise, g.Bind)
		}
		f := famIndex(fam)
		if g.Alt {
			alts[f]++
			observers[f]++
		} else {
			main = true
			observers[f] += portCount
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

// famIndex is the array index of a family: 0 for udp4, 1 for udp6.
func famIndex(f protocol.Family) int {
	if f == protocol.FamilyUDP6 {
		return 1
	}
	return 0
}
