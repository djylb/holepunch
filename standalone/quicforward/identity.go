package quicforward

import (
	"errors"
	"fmt"

	"github.com/djylb/holepunch/quicpath"
)

const (
	// Mode is the TransportMode of quicforward sessions.
	Mode = "quic"
	// ALPN is the QUIC application protocol of quicforward.
	ALPN = "holepunch-quicforward"
)

// ErrTransport is the error of a session whose transport decision or peer
// data does not allow quicforward.
var ErrTransport = errors.New("quicforward: session is not a pinned QUIC session")

// Identity is a QUIC TLS identity: a self-signed certificate whose pin is
// this side's TransportData (quicpath.Identity). Create it with
// NewIdentity; one identity may serve any number of sessions.
type Identity = quicpath.Identity

// NewIdentity creates a fresh identity for quicforward's ALPN.
func NewIdentity() (*Identity, error) {
	id, err := quicpath.NewIdentity(ALPN)
	if err != nil {
		return nil, fmt.Errorf("quicforward: %w", err)
	}
	return id, nil
}
