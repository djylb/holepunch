package holepunch_test

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/djylb/holepunch"
	"github.com/djylb/holepunch/coord"
	"github.com/djylb/holepunch/natprobe"
	"github.com/djylb/holepunch/nattest"
	"github.com/djylb/holepunch/protocol"
	"github.com/djylb/holepunch/udpwire"
)

// Example runs a whole deployment on a simulated Internet: a server with
// the NAT observer and the coordinator, and two clients behind NATs that
// punch a direct UDP path and send a datagram over it.
//
// A real deployment differs in three places only: the sockets are the
// operating system's (no Listen and no Network), the control connections
// are TLS or another authenticated, encrypted stream (no
// ControlSecurityInsecureForTesting), and the server pairs the two
// connections by its own matchmaking.
func Example() {
	n := nattest.NewNetwork(nattest.WithSeed(1))
	defer func() { _ = n.Close() }()
	server := n.PublicHost(netip.IPv4Unspecified())
	hosts := [2]*nattest.Host{
		n.NAT(nattest.PortRestricted()).Host(),
		n.NAT(nattest.SymmetricSeq(1)).Host(),
	}

	// Server side: natprobe measures the clients' NATs, the coordinator
	// runs the sessions and tells the clients where natprobe listens.
	reg := natprobe.NewRegistry(natprobe.RegistryConfig{})
	probe, err := natprobe.NewServer(natprobe.ServerConfig{
		Registry: reg,
		Groups:   []natprobe.ObserverGroup{{Bind: server.Addrs()[0]}},
		Listen:   server.Listen,
	})
	if err != nil {
		log.Fatal(err)
	}
	if err := probe.Start(); err != nil {
		log.Fatal(err)
	}
	defer func() { _ = probe.Close() }()
	co, err := coord.New(coord.Config{Registry: reg, DefaultProbe: probe.ProbeSpec()})
	if err != nil {
		log.Fatal(err)
	}
	defer func() { _ = co.Close() }()

	// One session pairs the two clients: each control connection is
	// attached to it under its role, and each client runs AttachSession on
	// its end.
	sess, err := co.NewSession(coord.SessionOptions{})
	if err != nil {
		log.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	var (
		wg       sync.WaitGroup
		ends     [2]net.Conn
		sessions [2]*holepunch.Session
		errs     [2]error
	)
	defer func() {
		for _, c := range ends {
			if c != nil {
				_ = c.Close()
			}
		}
	}()
	for i, role := range []protocol.Role{protocol.RoleInitiator, protocol.RoleResponder} {
		clientEnd, serverEnd := n.Pipe(nattest.PipeConfig{A: hosts[i], B: server})
		ends[i] = clientEnd
		err := sess.Attach(role, serverEnd, coord.AttachOptions{Security: protocol.ControlSecurityInsecureForTesting})
		if err != nil {
			log.Fatal(err)
		}
		wg.Go(func() {
			sessions[i], errs[i] = holepunch.AttachSession(ctx, clientEnd, holepunch.Options{
				ControlSecurity: protocol.ControlSecurityInsecureForTesting,
				Network:         hosts[i],
			})
		})
	}
	wg.Wait()
	if err := errors.Join(errs[:]...); err != nil {
		log.Fatal(err)
	}
	initiator, responder := sessions[0], sessions[1]
	defer func() { _ = initiator.Close() }()
	defer func() { _ = responder.Close() }()
	for _, s := range sessions {
		p := s.Result().Path
		fmt.Printf("%s: %s path over %s\n", s.Result().Role, p.Kind, p.Family)
	}

	// The sockets are the caller's now. An upper layer other than QUIC
	// filters the late handshake packets of the session out first.
	rf := responder.ResidualFilter()
	in := udpwire.DropResidual(responder.PacketConn(), rf.Codec, rf.Window)
	to := net.UDPAddrFromAddrPort(initiator.Result().Path.RemoteAddr)
	if _, err := initiator.PacketConn().WriteTo([]byte("hello"), to); err != nil {
		log.Fatal(err)
	}
	_ = in.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 1500)
	nr, _, err := in.ReadFrom(buf)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("responder read %q\n", buf[:nr])
	// Output:
	// initiator: public path over udp4
	// responder: public path over udp4
	// responder read "hello"
}

// ExampleAttachSession is the client side against a real server: the caller
// opens and authenticates the control connection, runs the session on it
// and, when no direct path is found, decides from the error whether and how
// to try again.
func ExampleAttachSession() {
	ctx := context.Background()
	var d tls.Dialer
	d.Config = &tls.Config{MinVersion: tls.VersionTLS13, ServerName: "coordinator.example"}
	conn, err := d.DialContext(ctx, "tcp", "coordinator.example:4343")
	if err != nil {
		log.Fatal(err)
	}
	// The connection stays the caller's: the library never closes it. Any
	// application messages before the session (a login, the peer's name) go
	// here, before AttachSession.
	defer func() { _ = conn.Close() }()

	sess, err := holepunch.AttachSession(ctx, conn, holepunch.Options{})
	if err != nil {
		var herr *holepunch.Error
		if !errors.As(err, &herr) {
			log.Fatal(err) // AttachSession only returns *holepunch.Error
		}
		switch {
		case herr.Advice == protocol.AdviceRelayOnly:
			log.Printf("no direct path to this peer (%s): keep the relay", herr.Reason)
		case herr.Advice == protocol.AdviceBackgroundViable:
			log.Printf("%v: serve over the relay and punch again with Options.Mode = protocol.ModeBackground", herr)
		case herr.Reason.Class() == protocol.ClassTransient:
			log.Printf("%v: try again in %v", herr, max(herr.RetryAfter, 5*time.Second))
		default: // fatal, nat_hard or canceled: retrying now would end the same way
			log.Printf("hole punching failed: %v", herr)
		}
		return
	}
	defer func() { _ = sess.Close() }()

	res := sess.Result()
	pc := sess.PacketConn()
	_, err = pc.WriteTo([]byte("hello"), net.UDPAddrFromAddrPort(res.Path.RemoteAddr))
	fmt.Println(res.Path.Kind, res.Path.RemoteAddr, err)
}
