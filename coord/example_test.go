package coord_test

import (
	"context"
	"crypto/tls"
	"errors"
	"log"
	"net"
	"net/netip"
	"time"

	"github.com/djylb/holepunch/coord"
	"github.com/djylb/holepunch/natprobe"
	"github.com/djylb/holepunch/protocol"
)

// Example is a minimal server on real sockets: natprobe observes the
// clients' NATs on the server's public IP, and a TLS listener pairs the
// clients two by two, the first of a pair as the initiator. Each client
// dials the listener and calls holepunch.AttachSession on its connection.
//
// A real server authenticates the clients and pairs them by its own
// matchmaking, usually with a few application messages on the same stream
// before the session (the standalone module does exactly that). It is only
// compiled: it needs a public IP.
func Example() {
	public := netip.MustParseAddr("203.0.113.10") // an address of this host

	reg := natprobe.NewRegistry(natprobe.RegistryConfig{})
	probe, err := natprobe.NewServer(natprobe.ServerConfig{
		Registry: reg,
		Groups:   []natprobe.ObserverGroup{{Bind: public}},
		BasePort: 3478, // UDP 3478-3480
	})
	if err != nil {
		log.Fatal(err)
	}
	if err := probe.Start(); err != nil {
		log.Fatal(err)
	}
	defer func() { _ = probe.Close() }()

	// Public STUN servers give the clients a second view of their mapping,
	// and a public address to a client on this server's own LAN.
	spec := probe.ProbeSpec()
	spec.STUN, err = natprobe.ResolveSTUN(context.Background(), nil, natprobe.DefaultSTUNServers())
	if err != nil {
		log.Print(err) // the servers that resolved are kept
	}
	co, err := coord.New(coord.Config{
		Registry:     reg,
		DefaultProbe: spec,
		OnResult: func(r coord.Result) {
			log.Printf("session %s %s %s", r.SessionID, r.Outcome, r.Code)
		},
	})
	if err != nil {
		log.Print(err)
		return
	}
	defer func() { _ = co.Close() }()

	cert, err := tls.LoadX509KeyPair("server.pem", "server.key")
	if err != nil {
		log.Print(err)
		return
	}
	l, err := tls.Listen("tcp", ":4343", &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{cert}})
	if err != nil {
		log.Print(err)
		return
	}
	defer func() { _ = l.Close() }()

	// handshake completes the TLS handshake: by default the coordinator
	// accepts only completed TLS connections.
	handshake := func(c net.Conn) error {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		return c.(*tls.Conn).HandshakeContext(ctx)
	}
	var waiting net.Conn // a client waiting for its peer
	for {
		c, err := l.Accept()
		if errors.Is(err, net.ErrClosed) {
			return
		}
		if err != nil {
			log.Print(err)
			continue
		}
		if err := handshake(c); err != nil {
			log.Print(err)
			_ = c.Close()
			continue
		}
		if waiting == nil {
			waiting = c
			continue
		}
		pair := [2]net.Conn{waiting, c}
		waiting = nil
		sess, err := co.NewSession(coord.SessionOptions{})
		if err != nil { // coord.ErrBusy, for one
			log.Print(err)
			_, _ = pair[0].Close(), pair[1].Close()
			continue
		}
		// Once Attach returns nil the connection is the session's, which
		// closes it when the session ends; after an error it is still ours.
		for i, role := range []protocol.Role{protocol.RoleInitiator, protocol.RoleResponder} {
			if err := sess.Attach(role, pair[i], coord.AttachOptions{}); err != nil {
				log.Print(err)
				_ = pair[i].Close()
				sess.Abort(protocol.ReasonCanceled, "attach_failed")
			}
		}
	}
}
