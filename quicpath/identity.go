package quicpath

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"time"

	"github.com/djylb/holepunch"
	"github.com/djylb/holepunch/protocol"
)

// pinPrefix marks a certificate pin in TransportData.
const pinPrefix = "sha256:"

// identityValidity is the validity of an Identity's certificate. Expiry plays
// no part, since peers verify the pin only.
const identityValidity = 365 * 24 * time.Hour

var (
	// ErrNoPin is the error of a peer whose TransportData carries no
	// certificate pin.
	ErrNoPin = errors.New("quicpath: peer transport data carries no certificate pin")
	// ErrPin is the error of a peer whose certificate does not have the
	// pin it announced.
	ErrPin = errors.New("quicpath: peer certificate does not match its pin")
)

// Identity is a TLS identity for QUIC: a self-signed ECDSA P-256 certificate
// whose pin, the SHA-256 of its DER encoding, is this side's TransportData.
// Create it with NewIdentity; one identity may serve any number of sessions.
type Identity struct {
	cert tls.Certificate
	pin  string // lower-case hex
	alpn string
}

// NewIdentity creates a fresh identity for the QUIC application protocol
// alpn, which both sides must use.
func NewIdentity(alpn string) (*Identity, error) {
	if alpn == "" {
		return nil, errors.New("quicpath: identity needs an application protocol")
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("quicpath: identity: %w", err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	if err != nil {
		return nil, fmt.Errorf("quicpath: identity: %w", err)
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: alpn},
		NotBefore:             now.Add(-time.Hour), // clock skew
		NotAfter:              now.Add(identityValidity),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, fmt.Errorf("quicpath: identity: %w", err)
	}
	return &Identity{
		cert: tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key},
		pin:  certPin(der),
		alpn: alpn,
	}, nil
}

// TransportData returns the TransportData that announces the identity's pin
// to the peer: holepunch.Options.TransportData.
func (id *Identity) TransportData() []byte { return []byte(pinPrefix + id.pin) }

// TLSConfig returns the TLS configuration of this side of the session res:
// a client's for the initiator, a server's for the responder. It presents
// the identity's certificate and accepts the peer only if its certificate
// has the pin of res.PeerTransportData (ErrNoPin if there is none).
//
// The pin replaces the chain verification and is checked on every
// handshake; the server issues no session ticket and the client keeps no
// session cache, so a connection never resumes a TLS session — it
// authenticates afresh.
func (id *Identity) TLSConfig(res holepunch.Result) (*tls.Config, error) {
	pin, err := PeerPin(res.PeerTransportData)
	if err != nil {
		return nil, err
	}
	switch res.Role {
	case protocol.RoleInitiator:
		return id.clientTLS(pin), nil
	case protocol.RoleResponder:
		return id.serverTLS(pin), nil
	default:
		return nil, fmt.Errorf("%w: role %q", ErrRole, res.Role)
	}
}

// serverTLS is the responder's configuration: the initiator must present
// the certificate with peerPin.
func (id *Identity) serverTLS(peerPin string) *tls.Config {
	return &tls.Config{
		MinVersion:             tls.VersionTLS13,
		Certificates:           []tls.Certificate{id.cert},
		ClientAuth:             tls.RequireAnyClientCert,
		VerifyConnection:       verifyPin(peerPin),
		SessionTicketsDisabled: true,
		NextProtos:             []string{id.alpn},
	}
}

// clientTLS is the initiator's configuration.
func (id *Identity) clientTLS(peerPin string) *tls.Config {
	return &tls.Config{
		MinVersion:         tls.VersionTLS13,
		Certificates:       []tls.Certificate{id.cert},
		InsecureSkipVerify: true, // the pin replaces the chain verification
		VerifyConnection:   verifyPin(peerPin),
		ServerName:         id.alpn,
		NextProtos:         []string{id.alpn},
	}
}

// PeerPin extracts the certificate pin from a peer's TransportData
// ("sha256:" and 64 hex digits; case and colons ignored) in lower-case hex.
func PeerPin(data []byte) (string, error) {
	p, ok := strings.CutPrefix(string(data), pinPrefix)
	if !ok {
		return "", ErrNoPin
	}
	pin := strings.ToLower(strings.ReplaceAll(strings.TrimSpace(p), ":", ""))
	if b, err := hex.DecodeString(pin); err != nil || len(b) != sha256.Size {
		return "", fmt.Errorf("%w: %q is not a hex SHA-256", ErrNoPin, p)
	}
	return pin, nil
}

// certPin returns the pin of a DER certificate.
func certPin(der []byte) string {
	sum := sha256.Sum256(der)
	return hex.EncodeToString(sum[:])
}

// verifyPin returns a tls.Config.VerifyConnection that accepts a peer only
// if its leaf certificate has the pin want.
//
// It is a VerifyConnection, not a VerifyPeerCertificate: crypto/tls skips
// VerifyPeerCertificate when it resumes a session, which would accept a
// ticket from a connection to another peer without any pin check.
// VerifyConnection runs on every handshake.
func verifyPin(want string) func(tls.ConnectionState) error {
	return func(cs tls.ConnectionState) error {
		if len(cs.PeerCertificates) == 0 {
			return ErrPin
		}
		got := certPin(cs.PeerCertificates[0].Raw)
		if subtle.ConstantTimeCompare([]byte(got), []byte(want)) != 1 {
			return ErrPin
		}
		return nil
	}
}
