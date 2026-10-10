package testworld

import (
	"context"
	"crypto/tls"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/djylb/holepunch"
	"github.com/djylb/holepunch/coord"
	"github.com/djylb/holepunch/natprobe"
	"github.com/djylb/holepunch/nattest"
	"github.com/djylb/holepunch/protocol"
	"github.com/djylb/holepunch/standalone/broker"
	"github.com/djylb/holepunch/standalone/client"
	"github.com/djylb/holepunch/standalone/internal/tlsid"
	"github.com/djylb/holepunch/standalone/server"
)

// ServerName is the TLS name of the world's server certificate.
const ServerName = "holepunchd.test"

// Timeouts are short protocol timeouts that keep every wait of a test
// session within a few seconds.
func Timeouts() protocol.Timeouts {
	return protocol.Timeouts{
		ProbeTimeoutMs: 600, SummaryWaitMs: 3000, GoWaitMs: 1500, HandshakeTimeoutMs: 4000,
		HandoverTimeoutMs: 1500, TransportTimeoutMs: 3000, MaxRounds: 3,
	}
}

// Options adjust a World.
type Options struct {
	Seed      int64
	PipeDelay time.Duration // one-way delay of the control links; 0 means 10 ms
	Broker    func(*broker.Config)
	Server    func(*server.Config)
}

// World is a simulated Internet with a standalone server on a public host:
// natprobe observers, a broker with its coordinator and the TLS front end.
// Clients behind simulated NATs reach the server through nattest pipes.
// Everything is closed by the test's cleanup.
type World struct {
	T         testing.TB
	Net       *nattest.Network
	Host      *nattest.Host // the server's host
	Registry  *natprobe.Registry
	Probe     *natprobe.Server
	Broker    *broker.Broker
	Server    *server.Server
	ClientTLS *tls.Config // pins the server's certificate

	pipeDelay time.Duration
}

// New builds a World.
func New(t testing.TB, o Options) *World {
	t.Helper()
	w := &World{T: t, pipeDelay: o.PipeDelay}
	if w.pipeDelay == 0 {
		w.pipeDelay = 10 * time.Millisecond
	}
	w.Net = nattest.NewNetwork(nattest.WithSeed(o.Seed))
	w.Host = w.Net.PublicHost(netip.IPv4Unspecified())
	w.Registry = natprobe.NewRegistry(natprobe.RegistryConfig{})
	probe, err := natprobe.NewServer(natprobe.ServerConfig{
		Registry: w.Registry, Groups: []natprobe.ObserverGroup{{Bind: w.Host.Addrs()[0]}},
		Listen: w.Host.Listen, SourceRate: natprobe.Rate{PerSec: -1},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := probe.Start(); err != nil {
		t.Fatal(err)
	}
	w.Probe = probe
	bcfg := broker.Config{Coord: coord.Config{
		Registry:     w.Registry,
		DefaultProbe: probe.ProbeSpec(),
		Timeouts:     Timeouts(),
	}}
	if o.Broker != nil {
		o.Broker(&bcfg)
	}
	w.Broker, err = broker.New(bcfg)
	if err != nil {
		t.Fatal(err)
	}
	cert, pin, err := tlsid.New(ServerName, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	scfg := server.Config{Broker: w.Broker, TLS: &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{cert}}}
	if o.Server != nil {
		o.Server(&scfg)
	}
	w.Server, err = server.New(scfg)
	if err != nil {
		t.Fatal(err)
	}
	w.ClientTLS = &tls.Config{
		MinVersion: tls.VersionTLS13, ServerName: ServerName,
		InsecureSkipVerify: true, VerifyPeerCertificate: tlsid.VerifyPin(pin),
	}
	t.Cleanup(func() {
		if err := w.Server.Close(); err != nil {
			t.Errorf("server close: %v", err)
		}
		if err := w.Broker.Close(); err != nil {
			t.Errorf("broker close: %v", err)
		}
		_ = probe.Close()
		_ = w.Net.Close()
	})
	return w
}

// Dial returns a Config.Dial for a client on h: every call opens a control
// link from h to the server's host and serves its far end.
func (w *World) Dial(h *nattest.Host) func(context.Context) (net.Conn, error) {
	return func(context.Context) (net.Conn, error) {
		a, b := w.Net.Pipe(nattest.PipeConfig{A: h, B: w.Host, DelayAB: w.pipeDelay, DelayBA: w.pipeDelay})
		if err := w.Server.ServeConn(b); err != nil {
			_ = a.Close()
			return nil, err
		}
		return a, nil
	}
}

// Client returns a client on h, closed by the test's cleanup; mutate, when
// set, adjusts its configuration.
func (w *World) Client(h *nattest.Host, mutate func(*client.Config)) *client.Client {
	w.T.Helper()
	cfg := client.Config{
		TLS: w.ClientTLS, Dial: w.Dial(h),
		Session: holepunch.Options{Network: h},
	}
	if mutate != nil {
		mutate(&cfg)
	}
	c, err := client.New(cfg)
	if err != nil {
		w.T.Fatal(err)
	}
	w.T.Cleanup(func() { _ = c.Close() })
	return c
}

// NATHost returns a host behind a new NAT of cfg.
func (w *World) NATHost(cfg nattest.NATConfig) *nattest.Host { return w.Net.NAT(cfg).Host() }

// Hairpin returns cfg with hairpinning on.
func Hairpin(cfg nattest.NATConfig) nattest.NATConfig {
	cfg.Hairpin = true
	return cfg
}
