package main

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"strings"
	"sync/atomic"
	"time"

	"github.com/djylb/holepunch/coord"
	"github.com/djylb/holepunch/internal/life"
	"github.com/djylb/holepunch/natprobe"
	"github.com/djylb/holepunch/protocol"
	"github.com/djylb/holepunch/standalone"
	"github.com/djylb/holepunch/standalone/broker"
	"github.com/djylb/holepunch/standalone/cmd/internal/cli"
	"github.com/djylb/holepunch/standalone/internal/tlsid"
	"github.com/djylb/holepunch/standalone/server"
	"github.com/djylb/holepunch/stun"
)

func main() {
	os.Exit(cli.Status(os.Stderr, "holepunchd", run(os.Args[1:])))
}

// How often the STUN servers' names are resolved again: stunRefresh, or
// stunRetry while the last resolution left none.
const (
	stunRefresh = 6 * time.Hour
	stunRetry   = time.Minute
)

// stunOff is the -stun value that turns STUN off.
const stunOff = "none"

// options are the command's flags.
type options struct {
	listen        string
	certFile      string
	keyFile       string
	token         string
	probeIPs      cli.StringList
	altIPs        cli.StringList
	stun          []string // host:port; nil: none
	probePort     int
	probePorts    int
	maxSessions   int
	heartbeat     time.Duration
	handshakeWait time.Duration
	noExtraReply  bool
	allowExtreme  bool
	verifiedOnly  bool
	debug         bool
}

// targets is the coordinator's target policy of the options.
func (o *options) targets() coord.TargetPolicy {
	if o.verifiedOnly {
		return coord.TargetsVerifiedOnly
	}
	return coord.TargetsBounded
}

func parse(args []string) (options, error) {
	var o options
	fs := flag.NewFlagSet("holepunchd", flag.ContinueOnError)
	fs.StringVar(&o.listen, "listen", ":4343", "TCP address of the TLS control listener")
	fs.StringVar(&o.certFile, "cert", "", "PEM certificate of the server (default: self-signed at every start)")
	fs.StringVar(&o.keyFile, "key", "", "PEM private key of -cert")
	fs.StringVar(&o.token, "auth-token", "", "shared token the clients must present")
	fs.Var(&o.probeIPs, "probe-ip", "public IP of a natprobe observer group, IP or BIND=ADVERTISE; repeatable, one at least")
	fs.Var(&o.altIPs, "probe-alt-ip", "second public IP for change-IP replies, IP or BIND=ADVERTISE; one per family")
	var stunFlag cli.StringList
	fs.Var(&stunFlag, "stun", "HOST:PORT or IP:PORT of a public STUN server the clients also ask, a second view of their mapping; repeatable; "+
		"the clients ask up to 8 of each address family at once, and a slow or blocked one costs them nothing; "+
		"none turns STUN off (default: a built-in list of servers on several continents, mainland China included)")
	fs.IntVar(&o.probePort, "probe-port", 3478, "first UDP port of the natprobe observers")
	fs.IntVar(&o.probePorts, "probe-ports", 3, "UDP ports per observer group (2..8)")
	fs.BoolVar(&o.noExtraReply, "no-extra-reply", false, "do not send natprobe's extra replies")
	fs.BoolVar(&o.allowExtreme, "allow-extreme", false, "allow the extreme per-round budget class")
	fs.BoolVar(&o.verifiedOnly, "verified-targets-only", false, "never aim at addresses a client only reported itself: "+
		"a client the server sees at a private address (on the server's LAN) then connects only to peers on that LAN")
	fs.IntVar(&o.maxSessions, "max-sessions", 0, "concurrent sessions (0: the coordinator's default)")
	fs.DurationVar(&o.heartbeat, "heartbeat", server.DefaultHeartbeat, "heartbeat interval of the host links")
	fs.DurationVar(&o.handshakeWait, "handshake-timeout", server.DefaultHandshakeTimeout, "bound of a client's TLS handshake and first request")
	fs.BoolVar(&o.debug, "debug", false, "log every coordinator event")
	if err := fs.Parse(args); err != nil {
		return o, err
	}
	if len(o.probeIPs) == 0 {
		return o, errors.New("at least one -probe-ip is required: natprobe binds each public address explicitly")
	}
	switch {
	case len(stunFlag) == 0:
		o.stun = stun.DefaultServers()
	case len(stunFlag) == 1 && stunFlag[0] == stunOff:
	default:
		for _, v := range stunFlag {
			if _, port, err := net.SplitHostPort(v); err != nil || port == "" || v == stunOff {
				return o, fmt.Errorf("-stun %q: want HOST:PORT, IP:PORT or a single %s", v, stunOff)
			}
		}
		o.stun = stunFlag
	}
	if (o.certFile == "") != (o.keyFile == "") {
		return o, errors.New("-cert and -key go together")
	}
	return o, nil
}

func run(args []string) error {
	o, err := parse(args)
	if err != nil {
		return err
	}
	log := cli.Logger(o.debug)
	if strings.TrimSpace(o.token) == "" {
		log.Warn("no -auth-token: any client that reaches the server can register hosts and open sessions")
	}
	tlsCfg, err := serverTLS(o, log)
	if err != nil {
		return err
	}
	groups, err := observerGroups(o)
	if err != nil {
		return err
	}
	reg := natprobe.NewRegistry(natprobe.RegistryConfig{})
	probe, err := natprobe.NewServer(natprobe.ServerConfig{
		Registry: reg, Groups: groups, BasePort: o.probePort, PortCount: o.probePorts,
		NoExtraReply: o.noExtraReply, Logger: log,
	})
	if err != nil {
		return err
	}
	defer func() { _ = probe.Close() }()
	if err := probe.Start(); err != nil {
		return fmt.Errorf("natprobe: %w", err)
	}
	for _, ob := range probe.ProbeSpec().Observers {
		log.Info("natprobe observer", "id", ob.ID, "addr", ob.Addr, "alt", ob.Alt)
	}
	ctx, stop := cli.SignalContext()
	defer stop()
	servers := &stunList{servers: o.stun, log: log}
	if len(o.stun) > 0 {
		servers.resolve(ctx)
		g := life.New(ctx)
		defer func() { _ = g.Close(0) }()
		g.Go("holepunchd.stun", servers.refresh)
	}
	// Every session gets natprobe's live observers and the STUN servers
	// as last resolved.
	probeSpec := func(protocol.Role, *coord.SessionOptions) (protocol.ProbeSpec, error) {
		spec := probe.ProbeSpec()
		spec.STUN = servers.get()
		return spec, nil
	}

	b, err := broker.New(broker.Config{Coord: coordConfig(o, reg, probeSpec, log)})
	if err != nil {
		return err
	}
	defer func() { _ = b.Close() }()
	srv, err := server.New(server.Config{
		Broker: b, TLS: tlsCfg, AuthToken: o.token, Logger: log,
		Heartbeat: o.heartbeat, HandshakeTimeout: o.handshakeWait,
		OnTransport: func(r server.TransportReport) {
			log.Info("transport", "host", r.HostID, "session", r.SessionID, "ok", r.OK, "detail", r.Detail)
		},
	})
	if err != nil {
		return err
	}
	defer func() { _ = srv.Close() }()
	l, err := standalone.ListenTCP(o.listen)
	if err != nil {
		return err
	}
	log.Info("listening", "addr", l.Addr())
	return serve(ctx, srv, l, log)
}

// serve runs the server until ctx ends (a signal); the server is closed
// before the broker and natprobe (run's deferred closes).
func serve(ctx context.Context, srv *server.Server, l net.Listener, log *slog.Logger) error {
	g := life.New(ctx)
	g.Go("holepunchd.shutdown", func(ctx context.Context) {
		<-ctx.Done()
		_ = srv.Close()
	})
	err := srv.Serve(l)
	_ = srv.Close()
	_ = g.Close(0)
	log.Info("stopped")
	return err
}

// serverTLS loads -cert/-key, or makes a self-signed certificate, and logs
// the pin the clients pass as -pin.
func serverTLS(o options, log *slog.Logger) (*tls.Config, error) {
	var cert tls.Certificate
	if o.certFile != "" {
		c, err := tls.LoadX509KeyPair(o.certFile, o.keyFile)
		if err != nil {
			return nil, err
		}
		cert = c
		log.Info("tls certificate", "pin", tlsid.Pin(cert.Certificate[0]))
	} else {
		c, pin, err := tlsid.New("holepunchd", 10*365*24*time.Hour)
		if err != nil {
			return nil, err
		}
		cert = c
		log.Warn("self-signed tls certificate; its pin changes at every start, use -cert/-key to keep it", "pin", pin)
	}
	return &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{cert}}, nil
}

// observerGroups turns -probe-ip and -probe-alt-ip into natprobe groups.
func observerGroups(o options) ([]natprobe.ObserverGroup, error) {
	var groups []natprobe.ObserverGroup
	for _, list := range []struct {
		values cli.StringList
		alt    bool
	}{{o.probeIPs, false}, {o.altIPs, true}} {
		for _, v := range list.values {
			bind, adv, err := bindAdvertise(v)
			if err != nil {
				return nil, err
			}
			groups = append(groups, natprobe.ObserverGroup{Bind: bind, Advertise: adv, Alt: list.alt})
		}
	}
	return groups, nil
}

// bindAdvertise parses IP or BIND=ADVERTISE.
func bindAdvertise(v string) (bind, adv netip.Addr, err error) {
	b, a, split := strings.Cut(v, "=")
	if bind, err = netip.ParseAddr(b); err != nil {
		return bind, adv, fmt.Errorf("probe address %q: %w", v, err)
	}
	if split {
		if adv, err = netip.ParseAddr(a); err != nil {
			return bind, adv, fmt.Errorf("probe address %q: %w", v, err)
		}
	}
	return bind, adv, nil
}

// coordConfig configures the coordinator: the probe spec every client
// receives, the operator's limits, and logging of every session's end (and
// of every event with -debug).
func coordConfig(o options, reg *natprobe.Registry, probe coord.ProbeFunc, log *slog.Logger) coord.Config {
	cfg := coord.Config{
		Registry: reg,
		Probe:    probe,
		Budget:   coord.BudgetConfig{AllowExtreme: o.allowExtreme},
		Limits:   coord.Limits{MaxSessions: o.maxSessions},
		Targets:  o.targets(),
		OnResult: func(r coord.Result) {
			log.Info("session", "id", r.SessionID, "host", r.Labels["host_id"], "dialer", r.Labels["dialer_id"],
				"outcome", r.Outcome, "code", r.Reason, "detail", r.Detail, "rounds", len(r.Rounds), "pair", r.PairClass)
		},
	}
	if o.debug {
		cfg.Observer = func(e coord.Event) {
			log.Debug("coord", "event", e.Kind, "session", e.SessionID, "role", e.Role, "round", e.Round,
				"code", e.Reason, "detail", e.Detail, "data", eventData(e.Data))
		}
	}
	return cfg
}

// eventData formats an event's data for the log; a recovered panic shows
// its value only, never its stack.
func eventData(d any) string {
	if p, ok := d.(coord.PanicInfo); ok {
		return "panic: " + p.Value
	}
	return fmt.Sprintf("%+v", d)
}

// stunList holds the STUN servers' addresses as last resolved.
type stunList struct {
	servers []string
	log     *slog.Logger
	cur     atomic.Pointer[[]netip.AddrPort]
}

// get returns the current addresses; nil before the first resolution.
func (s *stunList) get() []netip.AddrPort {
	if p := s.cur.Load(); p != nil {
		return *p
	}
	return nil
}

// resolve looks the servers up again. A resolution that finds none keeps
// the addresses found before.
func (s *stunList) resolve(ctx context.Context) {
	addrs, err := natprobe.ResolveSTUN(ctx, nil, s.servers)
	if err != nil {
		s.log.Warn("stun servers left out", "err", strings.ReplaceAll(err.Error(), "\n", "; "))
	}
	if len(addrs) > 0 || s.cur.Load() == nil {
		s.cur.Store(&addrs)
	}
	s.log.Info("stun servers", "addrs", s.get())
}

// refresh resolves the servers again every stunRefresh (stunRetry while
// there are none) until ctx ends.
func (s *stunList) refresh(ctx context.Context) {
	for {
		wait := stunRefresh
		if len(s.get()) == 0 {
			wait = stunRetry
		}
		t := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			t.Stop()
			return
		case <-t.C:
		}
		s.resolve(ctx)
	}
}
