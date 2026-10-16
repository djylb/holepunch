package clientcfg

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/netip"
	"os"

	"github.com/djylb/holepunch"
	"github.com/djylb/holepunch/portmapper"
	"github.com/djylb/holepunch/standalone/client"
	"github.com/djylb/holepunch/standalone/internal/tlsid"
)

// Flags are the flags every client command takes.
type Flags struct {
	Server     string
	Token      string
	CAFile     string
	Pin        string
	ServerName string
	LocalIP    string
	LocalIface string
	NoOverlay  bool
	PortMap    bool
	Debug      bool
}

// Register adds the flags to fs.
func (f *Flags) Register(fs *flag.FlagSet) {
	fs.StringVar(&f.Server, "server", "", "holepunchd address, host:port (required)")
	fs.StringVar(&f.Token, "auth-token", "", "the server's shared token")
	fs.StringVar(&f.Pin, "pin", "", "SHA-256 pin of the server certificate, as holepunchd prints it")
	fs.StringVar(&f.CAFile, "ca", "", "PEM file of CAs that sign the server certificate (default: system roots)")
	fs.StringVar(&f.ServerName, "server-name", "", "TLS name of the server (default: the host of -server)")
	fs.StringVar(&f.LocalIP, "local-ip", "", "preferred local IP for the punched UDP socket")
	fs.StringVar(&f.LocalIface, "local-interface", "", "preferred network interface for the punched UDP socket")
	fs.BoolVar(&f.NoOverlay, "exclude-overlay", false, "never punch through tunnel or overlay interfaces (Tailscale, WireGuard, ZeroTier, 100.64/10)")
	fs.BoolVar(&f.PortMap, "portmap", false, "ask the gateway for a port mapping (UPnP, NAT-PMP, PCP)")
	fs.BoolVar(&f.Debug, "debug", false, "log debug events")
}

// Config builds the client configuration. cleanup releases the port mapper,
// if one was created; it is never nil.
func (f *Flags) Config(log *slog.Logger) (cfg client.Config, cleanup func(), err error) {
	cleanup = func() {}
	if f.Server == "" {
		return cfg, cleanup, errors.New("-server is required")
	}
	tc, err := clientTLS(f.CAFile, f.Pin, f.ServerName)
	if err != nil {
		return cfg, cleanup, err
	}
	cfg = client.Config{Server: f.Server, TLS: tc, AuthToken: f.Token, Logger: log}
	if f.LocalIP != "" {
		ip, err := netip.ParseAddr(f.LocalIP)
		if err != nil {
			return cfg, cleanup, fmt.Errorf("-local-ip: %w", err)
		}
		cfg.Session.LocalAddr = ip
	}
	cfg.Session.LocalInterface = f.LocalIface
	cfg.Session.ExcludeOverlay = f.NoOverlay
	if f.PortMap {
		m := portmapper.New(portmapper.Config{Network: holepunch.SystemNetwork()})
		cfg.Session.PortMapper = m
		cleanup = func() { _ = m.Close() }
	}
	return cfg, cleanup, nil
}

// clientTLS authenticates the server by pin, by CA file, or by the system
// roots.
func clientTLS(caFile, pin, serverName string) (*tls.Config, error) {
	tc := &tls.Config{MinVersion: tls.VersionTLS13, ServerName: serverName}
	switch {
	case pin != "" && caFile != "":
		return nil, errors.New("-pin and -ca exclude each other")
	case pin != "":
		p, err := tlsid.ParsePin(pin)
		if err != nil {
			return nil, err
		}
		tc.InsecureSkipVerify = true // the pin replaces the chain verification
		tc.VerifyConnection = tlsid.VerifyPin(p)
	case caFile != "":
		pem, err := os.ReadFile(caFile)
		if err != nil {
			return nil, err
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("%s holds no PEM certificate", caFile)
		}
		tc.RootCAs = pool
	}
	return tc, nil
}
