package main

import (
	"log/slog"
	"slices"
	"testing"

	"go.uber.org/goleak"

	"github.com/djylb/holepunch/coord"
	"github.com/djylb/holepunch/protocol"
	"github.com/djylb/holepunch/stun"
)

func TestMain(m *testing.M) { goleak.VerifyTestMain(m) }

func TestParse(t *testing.T) {
	o, err := parse([]string{"-probe-ip", "10.0.0.5=203.0.113.5", "-probe-alt-ip", "203.0.113.6", "-auth-token", "t"})
	if err != nil {
		t.Fatal(err)
	}
	groups, err := observerGroups(o)
	if err != nil {
		t.Fatal(err)
	}
	if len(groups) != 2 || groups[0].Bind.String() != "10.0.0.5" || len(groups[0].Advertise) != 1 || groups[0].Advertise[0].String() != "203.0.113.5" ||
		groups[0].Alt || !groups[1].Alt || len(groups[1].Advertise) != 0 {
		t.Fatalf("groups %+v", groups)
	}
	if o, err := parse([]string{"-probe-ip", "0.0.0.0", "-auth-token", "t"}); err == nil {
		if _, err := observerGroups(o); err == nil {
			t.Error("a wildcard probe address without ADVERTISE accepted")
		}
	}
	if o, err := parse([]string{"-probe-ip", "0.0.0.0=203.0.113.5,198.51.100.7", "-auth-token", "t"}); err != nil {
		t.Fatal(err)
	} else if g, err := observerGroups(o); err != nil || len(g) != 1 || len(g[0].Advertise) != 2 || g[0].Advertise[1].String() != "198.51.100.7" {
		t.Fatalf("two addresses: %+v %v", g, err)
	}
	for _, args := range [][]string{
		{},
		{"-probe-ip", "1.2.3.4", "-cert", "c.pem"},
		{"-nonsense"},
		{"-probe-ip", "1.2.3.4", "-stun", "stun.example"},
		{"-probe-ip", "1.2.3.4", "-stun", "none", "-stun", "192.0.2.1:3478"},
	} {
		if _, err := parse(args); err == nil {
			t.Errorf("%v accepted", args)
		}
	}
	for _, v := range []string{"nope", "1.2.3.4=nope"} {
		if _, err := observerGroups(options{probeIPs: []string{v}}); err == nil {
			t.Errorf("%q accepted", v)
		}
	}
}

func TestSTUNFlag(t *testing.T) {
	for _, c := range []struct {
		args []string
		want []string
	}{
		{nil, stun.DefaultServers()},
		{[]string{"-stun", "none"}, nil},
		{[]string{"-stun", "stun.example:3478", "-stun", "192.0.2.1:3478"}, []string{"stun.example:3478", "192.0.2.1:3478"}},
	} {
		o, err := parse(append([]string{"-probe-ip", "1.2.3.4"}, c.args...))
		if err != nil {
			t.Fatalf("%v: %v", c.args, err)
		}
		if !slices.Equal(o.stun, c.want) {
			t.Fatalf("%v: stun %v, want %v", c.args, o.stun, c.want)
		}
	}
}

func TestCoordConfig(t *testing.T) {
	o := options{noExtraReply: true, allowExtreme: true, verifiedOnly: true, maxSessions: 7, debug: true}
	probe := func(protocol.Role, *coord.SessionOptions) (protocol.ProbeSpec, error) {
		return protocol.ProbeSpec{V: protocol.ProbeSpecVersion}, nil
	}
	cfg := coordConfig(o, nil, probe, nil)
	if cfg.Probe == nil || cfg.Targets != coord.TargetsVerifiedOnly || !cfg.Budget.AllowExtreme || cfg.Limits.MaxSessions != 7 ||
		cfg.Observer == nil || cfg.OnResult == nil {
		t.Fatalf("%+v", cfg)
	}
}

func TestServerTLS(t *testing.T) {
	cfg, err := serverTLS(options{}, discard())
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Certificates) != 1 {
		t.Fatalf("%d certificates", len(cfg.Certificates))
	}
	if _, err := serverTLS(options{certFile: "missing.pem", keyFile: "missing.key"}, discard()); err == nil {
		t.Fatal("missing certificate accepted")
	}
}

func discard() *slog.Logger { return slog.New(slog.DiscardHandler) }

func TestEventData(t *testing.T) {
	if got := eventData(coord.PanicInfo{Value: "boom", Stack: []byte("goroutine 1 [running]")}); got != "panic: boom" {
		t.Fatalf("%q", got)
	}
	if got := eventData(coord.AttachedData{ClientKey: "k"}); got != "{ClientKey:k}" {
		t.Fatalf("%q", got)
	}
}
