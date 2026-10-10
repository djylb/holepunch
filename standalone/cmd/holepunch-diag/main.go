package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"time"

	"github.com/djylb/holepunch/internal/life"
	"github.com/djylb/holepunch/protocol"
	"github.com/djylb/holepunch/standalone/client"
	"github.com/djylb/holepunch/standalone/cmd/internal/cli"
	"github.com/djylb/holepunch/standalone/cmd/internal/clientcfg"
)

// mode is the transport both sides offer, so that the server pairs them.
const mode = "udp_echo"

// idleLimit ends an echo session whose path stayed silent this long.
const idleLimit = 30 * time.Second

// pingMagic starts every diagnostic datagram.
const pingMagic = "hpdiag1"

const usage = `usage:
  holepunch-diag echo  -server ADDR -pin PIN -id ID
  holepunch-diag probe -server ADDR -pin PIN -id ID [-count 5] [-interval 500ms]`

func main() {
	if len(os.Args) < 2 {
		_, _ = fmt.Fprintln(os.Stderr, usage)
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "echo":
		err = runEcho(os.Args[2:])
	case "probe":
		err = runProbe(os.Args[2:])
	default:
		_, _ = fmt.Fprintln(os.Stderr, usage)
		os.Exit(2)
	}
	if err != nil {
		if !errors.Is(err, flag.ErrHelp) {
			_, _ = fmt.Fprintln(os.Stderr, "holepunch-diag:", err)
		}
		os.Exit(1)
	}
}

// newClient parses args and returns the Client they configure. cleanup
// releases what the configuration holds; the caller runs it after closing
// the Client.
func newClient(fs *flag.FlagSet, cf *clientcfg.Flags, args []string) (c *client.Client, cleanup func(), err error) {
	if err = fs.Parse(args); err != nil {
		return nil, nil, err
	}
	cfg, cleanup, err := cf.Config(cli.Logger(cf.Debug))
	if err != nil {
		return nil, nil, err
	}
	if c, err = client.New(cfg); err != nil {
		cleanup()
		return nil, nil, err
	}
	return c, cleanup, nil
}

func runEcho(args []string) error {
	var (
		cf clientcfg.Flags
		id string
	)
	fs := flag.NewFlagSet("holepunch-diag echo", flag.ContinueOnError)
	cf.Register(fs)
	fs.StringVar(&id, "id", "", "host ID to register (required)")
	c, cleanup, err := newClient(fs, &cf, args)
	if err != nil {
		return err
	}
	defer cleanup()
	defer func() { _ = c.Close() }()
	if id == "" {
		return errors.New("-id is required")
	}
	ctx, stop := cli.SignalContext()
	defer stop()
	fmt.Printf("echo host %s registered; waiting for sessions\n", id)
	return c.Serve(ctx, client.Registration{HostID: id, TransportMode: mode}, func(ctx context.Context, s *client.Session) {
		report(os.Stdout, s)
		n := echo(ctx, s)
		_ = s.ReportTransport(n > 0, fmt.Sprintf("echoed %d datagrams", n))
		fmt.Printf("session %s: echoed %d datagrams\n", s.ID(), n)
	})
}

// echo returns the punched peer's datagrams until ctx ends or the path is
// idle for idleLimit; it returns how many it echoed.
func echo(ctx context.Context, s *client.Session) int {
	pc := s.PacketConn()
	peer := s.Result().Path.RemoteAddr
	restore := life.InterruptRead(ctx, pc)
	defer func() { _ = restore() }()
	buf := make([]byte, 2048)
	n := 0
	for {
		if err := pc.SetReadDeadline(time.Now().Add(idleLimit)); err != nil || ctx.Err() != nil {
			return n
		}
		k, from, err := pc.ReadFrom(buf)
		if err != nil {
			return n
		}
		if !fromPeer(from, peer) || !bytes.HasPrefix(buf[:k], []byte(pingMagic)) {
			continue
		}
		if _, err := pc.WriteTo(buf[:k], from); err != nil {
			return n
		}
		n++
	}
}

func runProbe(args []string) error {
	var (
		cf       clientcfg.Flags
		id       string
		count    int
		interval time.Duration
	)
	fs := flag.NewFlagSet("holepunch-diag probe", flag.ContinueOnError)
	cf.Register(fs)
	fs.StringVar(&id, "id", "", "echo host ID to probe (required)")
	fs.IntVar(&count, "count", 5, "datagrams to send over the punched path")
	fs.DurationVar(&interval, "interval", 500*time.Millisecond, "time between datagrams")
	c, cleanup, err := newClient(fs, &cf, args)
	if err != nil {
		return err
	}
	defer cleanup()
	defer func() { _ = c.Close() }()
	if id == "" || count < 1 || interval <= 0 {
		return errors.New("-id is required, -count and -interval must be positive")
	}
	ctx, stop := cli.SignalContext()
	defer stop()
	start := time.Now()
	s, err := c.Open(ctx, client.OpenRequest{HostID: id, TransportMode: mode})
	if err != nil {
		return fmt.Errorf("punch failed after %v: %w", time.Since(start).Round(time.Millisecond), err)
	}
	defer func() { _ = s.Close() }()
	report(os.Stdout, s)
	return ping(ctx, os.Stdout, s, count, interval)
}

// ping sends count datagrams over the punched path and prints each
// round-trip time.
func ping(ctx context.Context, w io.Writer, s *client.Session, count int, interval time.Duration) error {
	pc := s.PacketConn()
	peer := net.UDPAddrFromAddrPort(s.Result().Path.RemoteAddr)
	buf := make([]byte, 2048)
	lost := 0
	for seq := range count {
		if seq > 0 && !pause(ctx, interval) {
			break
		}
		msg := binary.BigEndian.AppendUint32([]byte(pingMagic), uint32(seq))
		sent := time.Now()
		if _, err := pc.WriteTo(msg, peer); err != nil {
			return err
		}
		if err := awaitEcho(pc, buf, msg, s.Result().Path.RemoteAddr, sent.Add(time.Second)); err != nil {
			lost++
			_, _ = fmt.Fprintf(w, "seq=%d lost (%v)\n", seq, err)
			continue
		}
		_, _ = fmt.Fprintf(w, "seq=%d rtt=%v\n", seq, time.Since(sent).Round(10*time.Microsecond))
	}
	_, _ = fmt.Fprintf(w, "%d sent, %d lost\n", count, lost)
	return nil
}

// awaitEcho reads until the echo of msg arrives from peer or the deadline
// passes.
func awaitEcho(pc net.PacketConn, buf, msg []byte, peer netip.AddrPort, deadline time.Time) error {
	if err := pc.SetReadDeadline(deadline); err != nil {
		return err
	}
	defer func() { _ = pc.SetReadDeadline(time.Time{}) }()
	for {
		n, from, err := pc.ReadFrom(buf)
		if err != nil {
			return err
		}
		if fromPeer(from, peer) && bytes.Equal(buf[:n], msg) {
			return nil
		}
	}
}

func fromPeer(from net.Addr, peer netip.AddrPort) bool {
	ap, err := netip.ParseAddrPort(from.String())
	return err == nil && ap.Addr().Unmap() == peer.Addr().Unmap() && ap.Port() == peer.Port()
}

func pause(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return true
	case <-ctx.Done():
		return false
	}
}

// report prints how the session's punch went.
func report(w io.Writer, s *client.Session) {
	printf := func(format string, args ...any) { _, _ = fmt.Fprintf(w, format, args...) }
	res, diag := s.Result(), s.Diagnostics()
	info := s.Info()
	printf("session %s (%s) host=%s dialer=%s\n", s.ID(), res.Role, info.HostID, info.DialerID)
	printf("  path      %s %s %v -> %v, variant %s, %d round(s)\n", res.Path.Kind, res.Path.Family, res.Path.LocalAddr, res.Path.RemoteAddr, res.Variant, res.Rounds)
	for _, p := range res.ExtraPaths {
		printf("  extra     %s %s %v -> %v\n", p.Kind, p.Family, p.LocalAddr, p.RemoteAddr)
	}
	printf("  timing    probe %v, summary %v, go %v, punch %v, handover %v, total %v\n",
		res.Timing.Probe, res.Timing.SummaryWait, res.Timing.GoWait, res.Timing.Punch, res.Timing.Handover, res.Timing.Total)
	for _, t := range diag.Self {
		printf("  self  %-5s %s\n", t.Family, traits(t))
	}
	for _, t := range diag.Peer {
		printf("  peer  %-5s %s\n", t.Family, traits(t))
	}
	printf("  control   rtt %v\n", diag.RTT)
	printf("  keepalive every %v, dead after %v (%s)\n", res.Path.Keepalive.Interval, res.Path.Keepalive.Timeout, res.Path.Keepalive.Reason)
	if len(diag.Warn) > 0 {
		printf("  warnings  %v\n", diag.Warn)
	}
}

// traits formats the NAT traits of one family.
func traits(t protocol.Traits) string {
	return fmt.Sprintf("public %v, mapping %v, filtering %v, allocation %v (step %d), hairpin %v, cgnat %v, no NAT %v",
		t.PublicIP, t.Mapping, t.Filtering, t.PortAlloc, t.PortStep, t.Hairpin, t.CGNAT, t.NoNAT)
}
