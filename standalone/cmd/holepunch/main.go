package main

import (
	"errors"
	"flag"
	"fmt"
	"os"

	"github.com/djylb/holepunch/standalone"
	"github.com/djylb/holepunch/standalone/client"
	"github.com/djylb/holepunch/standalone/cmd/internal/cli"
	"github.com/djylb/holepunch/standalone/cmd/internal/clientcfg"
	"github.com/djylb/holepunch/standalone/quicforward"
)

const usage = `usage:
  holepunch host    -server ADDR -pin PIN -id ID -target HOST:PORT [-target ...]
  holepunch connect -server ADDR -pin PIN -id ID -listen 127.0.0.1:PORT [-target HOST:PORT]
run "holepunch host -h" or "holepunch connect -h" for every flag`

func main() {
	if len(os.Args) < 2 {
		_, _ = fmt.Fprintln(os.Stderr, usage)
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "host":
		err = runHost(os.Args[2:])
	case "connect":
		err = runConnect(os.Args[2:])
	default:
		_, _ = fmt.Fprintln(os.Stderr, usage)
		os.Exit(2)
	}
	if err != nil {
		if !errors.Is(err, flag.ErrHelp) {
			_, _ = fmt.Fprintln(os.Stderr, "holepunch:", err)
		}
		os.Exit(1)
	}
}

func runHost(args []string) error {
	var (
		cf      clientcfg.Flags
		targets cli.StringList
		id      string
	)
	fs := flag.NewFlagSet("holepunch host", flag.ContinueOnError)
	cf.Register(fs)
	fs.StringVar(&id, "id", "", "host ID the dialers connect to (required)")
	fs.Var(&targets, "target", "TCP target HOST:PORT the host forwards to; repeatable, the first is the default")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if id == "" || len(targets) == 0 {
		return errors.New("-id and at least one -target are required")
	}
	log := cli.Logger(cf.Debug)
	cfg, cleanup, err := cf.Config(log)
	if err != nil {
		return err
	}
	defer cleanup()
	c, err := client.New(cfg)
	if err != nil {
		return err
	}
	defer func() { _ = c.Close() }()
	ctx, stop := cli.SignalContext()
	defer stop()
	log.Info("serving", "id", id, "targets", targets)
	return quicforward.Serve(ctx, c, client.Registration{HostID: id}, quicforward.HostConfig{Targets: targets, Logger: log})
}

func runConnect(args []string) error {
	var (
		cf                        clientcfg.Flags
		id, dialerID, listen, tgt string
	)
	fs := flag.NewFlagSet("holepunch connect", flag.ContinueOnError)
	cf.Register(fs)
	fs.StringVar(&id, "id", "", "host ID to connect to (required)")
	fs.StringVar(&dialerID, "dialer-id", "", "this side's ID, shown to the host")
	fs.StringVar(&listen, "listen", "127.0.0.1:1080", "local TCP address to forward")
	fs.StringVar(&tgt, "target", "", "target HOST:PORT asked of the host (default: the host's default)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if id == "" {
		return errors.New("-id is required")
	}
	log := cli.Logger(cf.Debug)
	cfg, cleanup, err := cf.Config(log)
	if err != nil {
		return err
	}
	defer cleanup()
	c, err := client.New(cfg)
	if err != nil {
		return err
	}
	defer func() { _ = c.Close() }()
	l, err := standalone.ListenTCP(listen)
	if err != nil {
		return err
	}
	ctx, stop := cli.SignalContext()
	defer stop()
	log.Info("forwarding", "listen", l.Addr(), "host", id, "target", tgt)
	return quicforward.Connect(ctx, c, quicforward.ConnectConfig{
		Open: client.OpenRequest{HostID: id, DialerID: dialerID}, Listener: l, Target: tgt, Logger: log,
	})
}
