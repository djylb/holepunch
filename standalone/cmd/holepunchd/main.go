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
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		if !errors.Is(err, flag.ErrHelp) {
			_, _ = fmt.Fprintln(os.Stderr, "holepunchd:", err)
		}
		os.Exit(1)
	}
}

// maxSTUN is the number of STUN servers a probe spec lists at most.
const maxSTUN = 2

// options are the command's flags.
type options struct {
	listen        string
	certFile      string
	keyFile       string
	token         string
	probeIPs      cli.StringList
	altIPs        cli.StringList
	stun          []netip.AddrPort
	probePort     int
	probePorts    int
	noExtraReply  bool
	allowExtreme  bool
	maxSessions   int
	debug         bool
	heartbeat     time.Duration
	handshakeWait time.Duration
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
	var stun cli.StringList
	fs.Var(&stun, "stun", "IP:port of a third-party STUN server the clients also ask, a second view of their mapping; repeatable, two at most")
	fs.IntVar(&o.probePort, "probe-port", 3478, "first UDP port of the natprobe observers")
	fs.IntVar(&o.probePorts, "probe-ports", 3, "UDP ports per observer group (2..8)")
	fs.BoolVar(&o.noExtraReply, "no-extra-reply", false, "do not send natprobe's extra replies")
	fs.BoolVar(&o.allowExtreme, "allow-extreme", false, "allow the extreme per-round budget class")
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
	if len(stun) > maxSTUN {
		return o, fmt.Errorf("at most %d -stun servers", maxSTUN)
	}
	for _, v := range stun {
		ap, err := netip.ParseAddrPort(v)
		if err != nil {
			return o, fmt.Errorf("-stun %q: %w", v, err)
		}
		o.stun = append(o.stun, ap)
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
	observers := append(probe.Observers(protocol.FamilyUDP4), probe.Observers(protocol.FamilyUDP6)...)
	for _, ob := range observers {
		log.Info("natprobe observer", "id", ob.ID, "addr", ob.Addr, "alt", ob.Alt)
	}

	b, err := broker.New(broker.Config{Coord: coordConfig(o, reg, observers, log)})
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
	return serve(srv, l, log)
}

// serve runs the server until a signal; the server is closed before the
// broker and natprobe (run's deferred closes).
func serve(srv *server.Server, l net.Listener, log *slog.Logger) error {
	ctx, stop := cli.SignalContext()
	defer stop()
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

// coordConfig configures the coordinator: the observers every client
// probes, the operator's limits, and logging of every session's end (and of
// every event with -debug).
func coordConfig(o options, reg *natprobe.Registry, observers []protocol.ObserverSpec, log *slog.Logger) coord.Config {
	cfg := coord.Config{
		Registry: reg,
		DefaultProbe: protocol.ProbeSpec{
			V: protocol.ProbeSpecVersion, Observers: observers, ExtraReply: !o.noExtraReply, STUN: o.stun,
		},
		Budget: coord.BudgetConfig{AllowExtreme: o.allowExtreme},
		Limits: coord.Limits{MaxSessions: o.maxSessions},
		OnResult: func(r coord.Result) {
			log.Info("session", "id", r.SessionID, "host", r.Labels["host_id"], "dialer", r.Labels["dialer_id"],
				"outcome", r.Outcome, "code", r.Code, "detail", r.Detail, "rounds", len(r.Rounds), "pair", r.PairClass)
		},
	}
	if o.debug {
		cfg.Observer = func(e coord.Event) {
			log.Debug("coord", "event", e.Kind, "session", e.SessionID, "role", e.Role, "round", e.Round,
				"code", e.Code, "detail", e.Detail, "data", eventData(e.Data))
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
