package tlsid

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"strings"
	"testing"
	"time"

	"go.uber.org/goleak"

	"github.com/djylb/holepunch/nattest"
)

func TestMain(m *testing.M) { goleak.VerifyTestMain(m) }

func TestNewAndPin(t *testing.T) {
	cert, pin, err := New("example.test", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	if leaf.Subject.CommonName != "example.test" || leaf.NotAfter.Before(time.Now().Add(50*time.Minute)) || leaf.NotBefore.After(time.Now()) {
		t.Fatalf("certificate %v %v..%v", leaf.Subject, leaf.NotBefore, leaf.NotAfter)
	}
	if pin != Pin(cert.Certificate[0]) || len(pin) != 64 {
		t.Fatalf("pin %q", pin)
	}
	_, other, _ := New("example.test", time.Hour)
	if other == pin {
		t.Fatal("two identities share a pin")
	}
}

func TestParsePin(t *testing.T) {
	_, pin, _ := New("x", time.Hour)
	colons := strings.ToUpper(pin[:2]) + ":" + pin[2:]
	for _, in := range []string{pin, " " + strings.ToUpper(pin) + " ", colons} {
		if got, err := ParsePin(in); err != nil || got != pin {
			t.Errorf("%q: %q %v", in, got, err)
		}
	}
	for _, in := range []string{"", "zz", pin[:62], pin + "00"} {
		if _, err := ParsePin(in); err == nil {
			t.Errorf("%q accepted", in)
		}
	}
}

// handshake runs one TLS handshake over a buffered in-memory stream; the
// server then writes a byte, which the client reads so that it also takes
// the session ticket that precedes it. It returns the client's error and
// connection state.
func handshake(t *testing.T, n *nattest.Network, server, client *tls.Config) (tls.ConnectionState, error) {
	t.Helper()
	// TLS needs buffered streams: over net.Pipe the client's change cipher
	// spec and the server's first flight would wait for each other.
	a, b := n.Pipe(nattest.PipeConfig{})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	done := make(chan struct{})
	go func() {
		defer close(done)
		srv := tls.Server(b, server)
		if srv.HandshakeContext(ctx) == nil {
			_, _ = srv.Write([]byte{1})
		}
	}()
	defer func() {
		cancel()
		_ = a.Close()
		_ = b.Close()
		<-done
	}()
	cl := tls.Client(a, client)
	if err := cl.HandshakeContext(ctx); err != nil {
		return tls.ConnectionState{}, err
	}
	_ = cl.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := cl.Read(make([]byte, 1)); err != nil {
		t.Fatal(err)
	}
	return cl.ConnectionState(), nil
}

// TestVerifyPin: a TLS handshake succeeds only against the pinned
// certificate.
func TestVerifyPin(t *testing.T) {
	cert, pin, err := New("server.test", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	_, otherPin, _ := New("server.test", time.Hour)
	n := nattest.NewNetwork()
	defer func() { _ = n.Close() }()
	server := &tls.Config{Certificates: []tls.Certificate{cert}}
	for want, ok := range map[string]bool{pin: true, otherPin: false} {
		_, err := handshake(t, n, server, &tls.Config{InsecureSkipVerify: true, VerifyConnection: VerifyPin(want)})
		if (err == nil) != ok {
			t.Fatalf("pin match %v: %v", ok, err)
		}
		if !ok && !errors.Is(err, ErrPin) {
			t.Fatalf("error %v", err)
		}
	}
	if err := VerifyPin(pin)(tls.ConnectionState{}); !errors.Is(err, ErrPin) {
		t.Fatal("no certificate accepted")
	}
}

// TestVerifyPinOnResumption: a session ticket from a connection to one
// peer does not get a client past the pin of another. A check made in
// VerifyPeerCertificate is skipped on the resumed handshake; VerifyPin's is
// not.
func TestVerifyPinOnResumption(t *testing.T) {
	cert, pin, err := New("server.test", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	_, otherPin, _ := New("server.test", time.Hour)
	n := nattest.NewNetwork()
	defer func() { _ = n.Close() }()
	server := &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{cert}}
	cache := tls.NewLRUClientSessionCache(4)
	client := func() *tls.Config {
		return &tls.Config{MinVersion: tls.VersionTLS13, ServerName: "server.test", InsecureSkipVerify: true, ClientSessionCache: cache}
	}

	first := client()
	first.VerifyConnection = VerifyPin(pin)
	cs, err := handshake(t, n, server, first)
	if err != nil {
		t.Fatalf("first handshake: %v", err)
	}
	if cs.DidResume {
		t.Fatal("the first handshake resumed a session")
	}

	legacy := client()
	legacy.VerifyPeerCertificate = func(raw [][]byte, _ [][]*x509.Certificate) error {
		if len(raw) == 0 || Pin(raw[0]) != otherPin {
			return ErrPin
		}
		return nil
	}
	cs, err = handshake(t, n, server, legacy)
	if err != nil {
		t.Fatalf("the resumed handshake was expected to skip VerifyPeerCertificate: %v", err)
	}
	if !cs.DidResume {
		t.Fatal("the second handshake did not resume")
	}

	pinned := client()
	pinned.VerifyConnection = VerifyPin(otherPin)
	if _, err := handshake(t, n, server, pinned); !errors.Is(err, ErrPin) {
		t.Fatalf("resumed handshake with another pin: %v", err)
	}
}
