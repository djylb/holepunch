package quicforward

import (
	"crypto/tls"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/djylb/holepunch/standalone/internal/tlsid"
)

const (
	// Mode is the TransportMode of quicforward sessions.
	Mode = "quic"
	// ALPN is the QUIC application protocol of quicforward.
	ALPN = "holepunch-quicforward"
)

// pinPrefix marks a certificate pin in TransportData.
const pinPrefix = "sha256:"

// ErrTransport is the error of a session whose transport decision or peer
// data does not allow quicforward.
var ErrTransport = errors.New("quicforward: session is not a pinned QUIC session")

// Identity is a QUIC TLS identity: a self-signed certificate whose pin is
// this side's TransportData. Create it with NewIdentity; one identity may
// serve any number of sessions.
type Identity struct {
	cert tls.Certificate
	pin  string
}

// NewIdentity creates a fresh identity. Expiry plays no part, since peers
// verify the pin only.
func NewIdentity() (*Identity, error) {
	cert, pin, err := tlsid.New(ALPN, 365*24*time.Hour)
	if err != nil {
		return nil, fmt.Errorf("quicforward: identity: %w", err)
	}
	return &Identity{cert: cert, pin: pin}, nil
}

// TransportData returns the TransportData that announces the identity's pin
// to the peer.
func (id *Identity) TransportData() string { return pinPrefix + id.pin }

// peerPin extracts the peer's pin from its TransportData.
func peerPin(data string) (string, error) {
	p, ok := strings.CutPrefix(data, pinPrefix)
	if !ok {
		return "", ErrTransport
	}
	pin, err := tlsid.ParsePin(p)
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrTransport, err)
	}
	return pin, nil
}

// serverTLS is the host's QUIC TLS configuration: the dialer must present
// the certificate with peerPin.
func (id *Identity) serverTLS(peerPin string) *tls.Config {
	return &tls.Config{
		MinVersion:            tls.VersionTLS13,
		Certificates:          []tls.Certificate{id.cert},
		ClientAuth:            tls.RequireAnyClientCert,
		VerifyPeerCertificate: tlsid.VerifyPin(peerPin),
		NextProtos:            []string{ALPN},
	}
}

// clientTLS is the dialer's QUIC TLS configuration: the pin replaces the
// chain verification.
func (id *Identity) clientTLS(peerPin string) *tls.Config {
	return &tls.Config{
		MinVersion:            tls.VersionTLS13,
		Certificates:          []tls.Certificate{id.cert},
		InsecureSkipVerify:    true,
		VerifyPeerCertificate: tlsid.VerifyPin(peerPin),
		ServerName:            ALPN,
		NextProtos:            []string{ALPN},
	}
}
