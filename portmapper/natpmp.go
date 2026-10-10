package portmapper

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"time"

	"github.com/djylb/holepunch/internal/faultinject"
	"github.com/djylb/holepunch/protocol"
)

// NAT-PMP wire format (RFC 6886). It is implemented here rather than with
// go-nat-pmp, which cannot be cancelled by a context, retries for up to a
// minute on its own schedule, hard-codes port 5351 and opens its own sockets
// (every socket of a Mapper comes from Config.Network).
const (
	natpmpVersion    = 0 // also what a NAT-PMP-only server answers a PCP request with
	natpmpOpExternal = 0
	natpmpOpMapUDP   = 1
	natpmpOpReply    = 128
	natpmpExtRespLen = 12
	natpmpMapRespLen = 16
)

var natpmpResultNames = [...]string{
	"success", "unsupported version", "not authorized", "network failure", "out of resources", "unsupported opcode",
}

func natpmpError(code uint16) error {
	if code == 1 {
		return errNATPMPUnsupported
	}
	if int(code) < len(natpmpResultNames) {
		return fmt.Errorf("nat-pmp: gateway answered %q", natpmpResultNames[code])
	}
	return fmt.Errorf("nat-pmp: gateway answered result %d", code)
}

// natpmpHeader checks the common answer header. ok=false means b does not
// answer opcode op.
func natpmpHeader(b []byte, op byte, size int) (ok bool, err error) {
	if len(b) >= 2 && b[0] != natpmpVersion && b[1] >= natpmpOpReply {
		return false, errNATPMPUnsupported // for example a PCP server's UNSUPP_VERSION
	}
	if len(b) < 4 || b[0] != natpmpVersion || b[1] != natpmpOpReply+op {
		return false, nil
	}
	if code := binary.BigEndian.Uint16(b[2:4]); code != 0 {
		return false, natpmpError(code)
	}
	return len(b) >= size, nil
}

func buildNATPMPExternal() []byte { return []byte{natpmpVersion, natpmpOpExternal} }

func parseNATPMPExternal(b []byte) (netip.Addr, bool, error) {
	ok, err := natpmpHeader(b, natpmpOpExternal, natpmpExtRespLen)
	if !ok || err != nil {
		return netip.Addr{}, false, err
	}
	return netip.AddrFrom4([4]byte(b[8:12])), true, nil
}

func buildNATPMPMap(internalPort, suggestedPort uint16, lifetime uint32) []byte {
	pkt := make([]byte, 12)
	pkt[0] = natpmpVersion
	pkt[1] = natpmpOpMapUDP
	binary.BigEndian.PutUint16(pkt[4:6], internalPort)
	binary.BigEndian.PutUint16(pkt[6:8], suggestedPort)
	binary.BigEndian.PutUint32(pkt[8:12], lifetime)
	return pkt
}

// parseNATPMPMap returns the mapped external port and the granted lifetime
// from the answer to a map request for internalPort.
func parseNATPMPMap(b []byte, internalPort uint16) (external uint16, lifetime uint32, ok bool, err error) {
	ok, err = natpmpHeader(b, natpmpOpMapUDP, natpmpMapRespLen)
	if !ok || err != nil {
		return 0, 0, false, err
	}
	if binary.BigEndian.Uint16(b[8:10]) != internalPort {
		return 0, 0, false, nil
	}
	return binary.BigEndian.Uint16(b[10:12]), binary.BigEndian.Uint32(b[12:16]), true, nil
}

// natpmpProbe is a gateway that answered the external address request, the
// side-effect-free check that runs in parallel with PCP.
type natpmpProbe struct {
	open     opener
	server   netip.AddrPort
	client   netip.Addr // the address requests are sent from
	external netip.Addr
}

func natpmpDiscover(ctx context.Context, open opener, server netip.AddrPort, client netip.Addr) (*natpmpProbe, error) {
	c, err := open(ctx, client)
	if err != nil {
		return nil, fmt.Errorf("nat-pmp: %w", err)
	}
	defer c.Close()
	var ext netip.Addr
	_, err = c.exchange(ctx, server, buildNATPMPExternal(), func(b []byte) (bool, error) {
		a, ok, err := parseNATPMPExternal(b)
		if ok {
			ext = a
		}
		return ok, err
	})
	if err != nil {
		return nil, fmt.Errorf("nat-pmp: %w", err)
	}
	if ext.IsUnspecified() {
		return nil, errors.New("nat-pmp: gateway has no external address")
	}
	return &natpmpProbe{open: open, server: server, client: client, external: ext}, nil
}

// natpmpMapping is one live NAT-PMP mapping, owned by its lease.
type natpmpMapping struct {
	open     opener
	server   netip.AddrPort
	client   netip.Addr
	port     uint16 // internal port
	external netip.AddrPort
	lifetime uint32 // requested lifetime, seconds
}

// create is the probe's creator: it requests a mapping of the probe's client
// address and port.
func (p *natpmpProbe) create(ctx context.Context, port uint16, lease time.Duration) (live liveMapping, info protocol.PortMappingInfo, orphan remover, err error) {
	if err := faultinject.Point(pointMap); err != nil {
		return nil, info, nil, err
	}
	nm := &natpmpMapping{open: p.open, server: p.server, client: p.client, port: port, lifetime: uint32(lease / time.Second)}
	extPort, lifetime, out, err := nm.request(ctx, port, nm.lifetime)
	if err != nil {
		if out == unanswered {
			orphan = nm
		}
		return nil, info, orphan, fmt.Errorf("nat-pmp: %w", err)
	}
	nm.external = netip.AddrPortFrom(p.external, extPort)
	if err := validMapping(nm.external, lifetime); err != nil {
		return nil, info, nm, fmt.Errorf("nat-pmp: %w", err)
	}
	info = protocol.PortMappingInfo{
		Method:   protocol.PortMapNATPMP,
		External: nm.external,
		Internal: netip.AddrPortFrom(p.client, port),
		Lease:    time.Duration(lifetime) * time.Second,
	}
	return nm, info, nil, nil
}

func (nm *natpmpMapping) request(ctx context.Context, suggested uint16, lifetime uint32) (extPort uint16, granted uint32, out outcome, err error) {
	c, err := nm.open(ctx, nm.client)
	if err != nil {
		return 0, 0, notSent, err
	}
	defer c.Close()
	out, err = c.exchange(ctx, nm.server, buildNATPMPMap(nm.port, suggested, lifetime), func(b []byte) (bool, error) {
		e, l, ok, err := parseNATPMPMap(b, nm.port)
		if ok {
			extPort, granted = e, l
		}
		return ok, err
	})
	return extPort, granted, out, err
}

func (nm *natpmpMapping) renew(ctx context.Context) (time.Duration, error) {
	extPort, lifetime, _, err := nm.request(ctx, nm.external.Port(), nm.lifetime)
	if err == nil {
		err = validMapping(netip.AddrPortFrom(nm.external.Addr(), extPort), lifetime)
	}
	if err != nil {
		return 0, fmt.Errorf("nat-pmp renew: %w", err)
	}
	nm.external = netip.AddrPortFrom(nm.external.Addr(), extPort)
	return time.Duration(lifetime) * time.Second, nil
}

// remove deletes the mapping: a map request with lifetime 0 and suggested
// external port 0 (RFC 6886, section 3.4).
func (nm *natpmpMapping) remove(ctx context.Context) error {
	if _, _, _, err := nm.request(ctx, 0, 0); err != nil {
		return fmt.Errorf("nat-pmp delete: %w", err)
	}
	return nil
}
