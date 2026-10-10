package main

import (
	"log/slog"
	"testing"

	"go.uber.org/goleak"

	"github.com/djylb/holepunch/coord"
	"github.com/djylb/holepunch/protocol"
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
	if len(groups) != 2 || groups[0].Bind.String() != "10.0.0.5" || groups[0].Advertise.String() != "203.0.113.5" ||
		groups[0].Alt || !groups[1].Alt || groups[1].Advertise.IsValid() {
		t.Fatalf("groups %+v", groups)
	}
	for _, args := range [][]string{
		{},
		{"-probe-ip", "1.2.3.4", "-cert", "c.pem"},
		{"-nonsense"},
		{"-probe-ip", "1.2.3.4", "-stun", "stun.example:3478"},
		{"-probe-ip", "1.2.3.4", "-stun", "192.0.2.1:3478", "-stun", "192.0.2.2:3478", "-stun", "192.0.2.3:3478"},
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

func TestCoordConfig(t *testing.T) {
	o := options{noExtraReply: true, allowExtreme: true, maxSessions: 7, debug: true}
	p, err := parse([]string{"-probe-ip", "1.2.3.4", "-stun", "192.0.2.1:3478"})
	if err != nil {
		t.Fatal(err)
	}
	if len(p.stun) != 1 {
		t.Fatalf("-stun: %+v", p.stun)
	}
	o.stun = p.stun
	spec := protocol.ProbeSpec{V: protocol.ProbeSpecVersion, Observers: []protocol.ObserverSpec{{ID: 1}}, STUN: o.stun}
	cfg := coordConfig(o, nil, spec, nil)
	if len(cfg.DefaultProbe.Observers) != 1 || cfg.DefaultProbe.V != protocol.ProbeSpecVersion || len(cfg.DefaultProbe.STUN) != 1 ||
		!cfg.Budget.AllowExtreme || cfg.Limits.MaxSessions != 7 || cfg.Observer == nil || cfg.OnResult == nil {
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
