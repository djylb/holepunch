package quicforward

import (
	"bytes"
	"context"
	"errors"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/djylb/holepunch"
	"github.com/djylb/holepunch/standalone/proto"
)

func TestStreamFrames(t *testing.T) {
	var buf bytes.Buffer
	if err := writeFrame(&buf, streamRequest{Target: "a.test:1"}); err != nil {
		t.Fatal(err)
	}
	var req streamRequest
	if err := readFrame(&buf, &req); err != nil || req.Target != "a.test:1" {
		t.Fatalf("%+v %v", req, err)
	}
	if err := writeFrame(&buf, streamRequest{Target: strings.Repeat("x", maxStreamFrame)}); err == nil {
		t.Fatal("oversized frame written")
	}
	if err := readFrame(bytes.NewReader([]byte{0xff, 0xff}), &req); err == nil {
		t.Fatal("oversized frame read")
	}
	if err := readFrame(bytes.NewReader([]byte{0, 5, '{'}), &req); err == nil {
		t.Fatal("truncated frame read")
	}
	if err := readFrame(bytes.NewReader(nil), &req); err == nil {
		t.Fatal("empty stream read")
	}
	if err := writeFrame(&buf, make(chan int)); err == nil {
		t.Fatal("unencodable value written")
	}
}

func TestResolve(t *testing.T) {
	cfg, err := HostConfig{Targets: []string{"A.test:1", "[::1]:22"}}.normalize()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Dial == nil || cfg.Logger == nil || cfg.DialTimeout != DefaultDialTimeout {
		t.Fatalf("defaults %+v", cfg)
	}
	open := proto.AccessPolicy{}
	only := proto.AccessPolicy{Targets: []string{"[::1]:22"}}
	for _, c := range []struct {
		req    string
		policy proto.AccessPolicy
		want   string
	}{
		{"", open, "a.test:1"},
		{"a.TEST:01", open, "a.test:1"},
		{"[0:0::1]:22", open, "[::1]:22"},
		{"[::1]:22", only, "[::1]:22"},
		{"", only, ""},
		{"b.test:1", open, ""},
		{"nonsense", open, ""},
	} {
		got, err := cfg.resolve(c.req, c.policy)
		if got != c.want || (c.want == "") != (err != nil) {
			t.Errorf("%q %v: %q %v", c.req, c.policy, got, err)
		}
	}
}

func TestPeerPin(t *testing.T) {
	id, err := NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	if pin, err := peerPin(id.TransportData()); err != nil || pin != id.pin {
		t.Fatalf("%q %v", pin, err)
	}
	for _, bad := range []string{"", id.pin, "sha256:", "sha256:zz", "md5:" + id.pin} {
		if _, err := peerPin(bad); !errors.Is(err, ErrTransport) {
			t.Errorf("%q: %v", bad, err)
		}
	}
}

func TestSameAddr(t *testing.T) {
	want := netip.MustParseAddrPort("203.0.113.7:4000")
	for a, ok := range map[net.Addr]bool{
		&net.UDPAddr{IP: net.ParseIP("203.0.113.7"), Port: 4000}:        true,
		&net.UDPAddr{IP: net.ParseIP("::ffff:203.0.113.7"), Port: 4000}: true,
		&net.UDPAddr{IP: net.ParseIP("203.0.113.7"), Port: 4001}:        false,
		&net.UDPAddr{IP: net.ParseIP("203.0.113.8"), Port: 4000}:        false,
		&net.UnixAddr{Name: "x", Net: "unix"}:                           false,
	} {
		if sameAddr(a, want) != ok {
			t.Errorf("%v: %v", a, !ok)
		}
	}
	if sameAddr(nil, want) {
		t.Fatal("nil address matched")
	}
}

func TestQUICConfig(t *testing.T) {
	c := quicConfig(holepunch.Result{})
	if c.HandshakeIdleTimeout != defaultTransportTimeout || c.MaxIdleTimeout != defaultIdleTimeout || c.KeepAlivePeriod != defaultIdleTimeout/3 {
		t.Fatalf("defaults %+v", c)
	}
	c = quicConfig(holepunch.Result{TransportTimeout: 3 * time.Second, Path: holepunch.Path{Keepalive: holepunch.KeepaliveAdvice{Interval: 10 * time.Second, Timeout: 30 * time.Second}}})
	if c.HandshakeIdleTimeout != 3*time.Second || c.MaxIdleTimeout != 30*time.Second || c.KeepAlivePeriod != 10*time.Second {
		t.Fatalf("advice %+v", c)
	}
}

func TestPause(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if pause(ctx, time.Hour) {
		t.Fatal("pause outlived its context")
	}
	if !pause(context.Background(), time.Millisecond) {
		t.Fatal("pause interrupted")
	}
}

// FuzzStreamRequest: whatever a dialer writes as a stream's request, the
// host never panics and never resolves a target outside its list.
func FuzzStreamRequest(f *testing.F) {
	var buf bytes.Buffer
	_ = writeFrame(&buf, streamRequest{Target: "a.test:1"})
	f.Add(buf.Bytes())
	f.Add([]byte{0, 2, '{', '}'})
	f.Add([]byte{0xff, 0xff})
	cfg, err := HostConfig{Targets: []string{"a.test:1", "[::1]:22"}}.normalize()
	if err != nil {
		f.Fatal(err)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		var req streamRequest
		if readFrame(bytes.NewReader(data), &req) != nil {
			return
		}
		target, err := cfg.resolve(req.Target, proto.AccessPolicy{})
		if err == nil && target != "a.test:1" && target != "[::1]:22" {
			t.Fatalf("resolved %q", target)
		}
	})
}
