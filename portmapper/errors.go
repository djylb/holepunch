package portmapper

import (
	"errors"
	"fmt"
	"net"
	"strings"
)

var (
	// ErrNoGateway reports that no gateway was found: the default gateway
	// lookup failed or timed out, or the host has no IPv4 route out, and no
	// UPnP gateway answered either.
	ErrNoGateway = errors.New("portmapper: no gateway found")
	// ErrUnsupported reports that no method the policy allows produced a
	// mapping: nothing answered, the gateway refused, or the socket is not
	// IPv4. The error also wraps each method's failure.
	ErrUnsupported = errors.New("portmapper: port mapping unavailable")
)

var (
	errMapperClosed = fmt.Errorf("portmapper: mapper closed: %w", net.ErrClosed)
	errNoNetwork    = errors.New("portmapper: Config.Network is nil")
	errNilConn      = errors.New("portmapper: nil conn")
	errNoConn       = errors.New("Network.ListenPacket returned no conn")
	errRenewStuck   = errors.New("portmapper: renewal did not stop in time; the mapping is left to expire")

	// errDiscoverTimeout is the cause of a Map's discovery deadline.
	errDiscoverTimeout = errors.New("gateway discovery timed out")
	// errNoResponse marks a request that was sent but never answered: the
	// gateway may have acted on it.
	errNoResponse = errors.New("no response from gateway")

	errNoDefaultRoute    = errors.New("no IPv4 default route")
	errNotIPv4Gateway    = errors.New("default gateway is not IPv4")
	errPCPUnsupported    = errors.New("pcp: gateway does not support PCP version 2")
	errNATPMPUnsupported = errors.New("nat-pmp: gateway does not support NAT-PMP")
	errNoIGD             = errors.New("upnp: no internet gateway device answered")
	errBodyTooLarge      = errors.New("upnp: response body too large")
)

// multiError keeps the failure of every method a Map tried. Unlike
// errors.Join it prints on one line, since the text ends up in logs and
// diagnostics.
type multiError []error

func (e multiError) Error() string {
	parts := make([]string, len(e))
	for i, err := range e {
		parts[i] = err.Error()
	}
	return strings.Join(parts, "; ")
}

func (e multiError) Unwrap() []error { return e }
