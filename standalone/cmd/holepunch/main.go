package main

import (
	"errors"
	"flag"
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
	cli.Dispatch("holepunch", usage, os.Args[1:], map[string]func([]string) error{
		"host":    runHost,
		"connect": runConnect,
	})
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
	c, err := cf.NewClient(log)
	if err != nil {
		return err
	}
	defer func() { _ = c.Close() }()
	ctx, stop := cli.SignalContext()
	defer stop()
	log.Info("serving", "id", id, "targets", targets)
	return quicforward.Serve(ctx, c.Client, client.Registration{HostID: id}, quicforward.HostConfig{Targets: targets, Logger: log})
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
	c, err := cf.NewClient(log)
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
	return quicforward.Connect(ctx, c.Client, quicforward.ConnectConfig{
		Open: client.OpenRequest{HostID: id, DialerID: dialerID}, Listener: l, Target: tgt, Logger: log,
	})
}
