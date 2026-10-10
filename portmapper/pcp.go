package portmapper

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"time"

	"github.com/djylb/holepunch/internal/faultinject"
	"github.com/djylb/holepunch/protocol"
)

// PCP wire format (RFC 6887). Only the MAP opcode for UDP is used.
const (
	pcpVersion   = 2
	pcpOpMap     = 1
	pcpOpReply   = 0x80
	pcpProtoUDP  = 17
	pcpHeaderLen = 24
	pcpMapLen    = 36
	pcpMapMsgLen = pcpHeaderLen + pcpMapLen
)

type pcpResultCode uint8

const (
	pcpSuccess         pcpResultCode = 0
	pcpUnsuppVersion   pcpResultCode = 1
	pcpNotAuthorized   pcpResultCode = 2
	pcpAddressMismatch pcpResultCode = 12
)

var pcpResultNames = [...]string{
	"SUCCESS", "UNSUPP_VERSION", "NOT_AUTHORIZED", "MALFORMED_REQUEST", "UNSUPP_OPCODE",
	"UNSUPP_OPTION", "MALFORMED_OPTION", "NETWORK_FAILURE", "NO_RESOURCES", "UNSUPP_PROTOCOL",
	"USER_EX_QUOTA", "CANNOT_PROVIDE_EXTERNAL", "ADDRESS_MISMATCH", "EXCESSIVE_REMOTE_PEERS",
}

func (c pcpResultCode) String() string {
	if int(c) < len(pcpResultNames) {
		return pcpResultNames[c]
	}
	return fmt.Sprintf("result(%d)", uint8(c))
}

// pcpMapResponse is a parsed and validated MAP answer.
type pcpMapResponse struct {
	code     pcpResultCode
	lifetime uint32
	external netip.AddrPort
}

// buildPCPMap encodes a MAP request for a UDP mapping of client:internalPort.
// suggested is the external address hint; an invalid suggested address means
// "no preference" for an IPv4 external address, ::ffff:0.0.0.0 (RFC 6887,
// section 11.1). One mapping uses the same nonce for its create, every
// renewal and its delete (RFC 6887, section 11.2).
func buildPCPMap(client netip.Addr, nonce [12]byte, internalPort uint16, suggested netip.AddrPort, lifetime uint32) []byte {
	pkt := make([]byte, pcpMapMsgLen)
	pkt[0] = pcpVersion
	pkt[1] = pcpOpMap
	binary.BigEndian.PutUint32(pkt[4:8], lifetime)
	clientIP := client.As16()
	copy(pkt[8:24], clientIP[:])

	op := pkt[pcpHeaderLen:]
	copy(op[0:12], nonce[:])
	op[12] = pcpProtoUDP
	binary.BigEndian.PutUint16(op[16:18], internalPort)
	binary.BigEndian.PutUint16(op[18:20], suggested.Port())
	extIP := netip.IPv4Unspecified()
	if suggested.Addr().IsValid() {
		extIP = suggested.Addr()
	}
	ext16 := extIP.As16()
	copy(op[20:36], ext16[:])
	return pkt
}

// parsePCPMap checks whether b answers the MAP request identified by nonce
// and internalPort. It returns ok=false for datagrams that are not that
// answer and an error for a definitive negative answer.
func parsePCPMap(b []byte, nonce [12]byte, internalPort uint16) (resp pcpMapResponse, ok bool, err error) {
	if len(b) >= 2 && b[0] == natpmpVersion && b[1] >= pcpOpReply {
		return resp, false, errPCPUnsupported // a NAT-PMP-only server answers with version 0
	}
	if len(b) < pcpHeaderLen || b[0] != pcpVersion || b[1] != pcpOpMap|pcpOpReply {
		return resp, false, nil
	}
	resp.code = pcpResultCode(b[3])
	resp.lifetime = binary.BigEndian.Uint32(b[4:8])
	if len(b) < pcpMapMsgLen {
		if resp.code != pcpSuccess {
			// An error answer may omit the opcode payload; there is nothing to match.
			return resp, false, pcpError(resp.code)
		}
		return resp, false, nil
	}
	op := b[pcpHeaderLen:]
	if [12]byte(op[0:12]) != nonce || binary.BigEndian.Uint16(op[16:18]) != internalPort {
		return resp, false, nil // another request's answer
	}
	if resp.code != pcpSuccess {
		return resp, false, pcpError(resp.code)
	}
	if op[12] != pcpProtoUDP {
		return resp, false, fmt.Errorf("pcp: answer for protocol %d, want UDP", op[12])
	}
	resp.external = netip.AddrPortFrom(netip.AddrFrom16([16]byte(op[20:36])).Unmap(), binary.BigEndian.Uint16(op[18:20]))
	return resp, true, nil
}

func pcpError(code pcpResultCode) error {
	if code == pcpUnsuppVersion {
		return errPCPUnsupported
	}
	return fmt.Errorf("pcp: gateway answered %s", code)
}

// pcpMapping is one live PCP mapping, owned by its lease.
type pcpMapping struct {
	open     opener
	server   netip.AddrPort // gateway:5351
	client   netip.Addr     // PCP client address; requests are sent from it
	nonce    [12]byte
	port     uint16         // internal port
	external netip.AddrPort // last assigned external address
	lifetime uint32         // requested lifetime, seconds
}

// pcpCreate requests a new mapping of client:port. When the gateway may hold
// a mapping although the request failed — the request was sent but not
// answered, or the answer is unusable — it is returned as orphan, for the
// caller to delete.
func pcpCreate(ctx context.Context, open opener, server netip.AddrPort, client netip.Addr, port uint16, lease time.Duration) (live liveMapping, info protocol.PortMappingInfo, orphan remover, err error) {
	if err := faultinject.Point(pointMap); err != nil {
		return nil, info, nil, err
	}
	p := &pcpMapping{open: open, server: server, client: client, port: port, lifetime: uint32(lease / time.Second)}
	_, _ = rand.Read(p.nonce[:]) // never fails since Go 1.24
	// Suggest the internal port as the external one: a gateway that keeps the
	// port number gives peers a predictable target.
	resp, out, err := p.request(ctx, netip.AddrPortFrom(netip.Addr{}, port), p.lifetime)
	if err != nil {
		if out == unanswered {
			orphan = p
		}
		return nil, info, orphan, fmt.Errorf("pcp: %w", err)
	}
	p.external = resp.external
	if err := validMapping(resp.external, resp.lifetime); err != nil {
		return nil, info, p, fmt.Errorf("pcp: %w", err)
	}
	info = protocol.PortMappingInfo{
		Method:   protocol.PortMapPCP,
		External: resp.external,
		Internal: netip.AddrPortFrom(client, port),
		Lease:    time.Duration(resp.lifetime) * time.Second,
	}
	return p, info, nil, nil
}

func (p *pcpMapping) request(ctx context.Context, suggested netip.AddrPort, lifetime uint32) (pcpMapResponse, outcome, error) {
	c, err := p.open(ctx, p.client)
	if err != nil {
		return pcpMapResponse{}, notSent, err
	}
	defer c.Close()
	var resp pcpMapResponse
	out, err := c.exchange(ctx, p.server, buildPCPMap(p.client, p.nonce, p.port, suggested, lifetime), func(b []byte) (bool, error) {
		r, ok, err := parsePCPMap(b, p.nonce, p.port)
		if ok {
			resp = r
		}
		return ok, err
	})
	return resp, out, err
}

func (p *pcpMapping) renew(ctx context.Context) (time.Duration, error) {
	resp, _, err := p.request(ctx, p.external, p.lifetime)
	if err == nil {
		err = validMapping(resp.external, resp.lifetime)
	}
	if err != nil {
		return 0, fmt.Errorf("pcp renew: %w", err)
	}
	p.external = resp.external
	return time.Duration(resp.lifetime) * time.Second, nil
}

// remove deletes the mapping: a MAP request with lifetime 0 and the
// mapping's nonce (RFC 6887, section 15).
func (p *pcpMapping) remove(ctx context.Context) error {
	if _, _, err := p.request(ctx, p.external, 0); err != nil {
		return fmt.Errorf("pcp delete: %w", err)
	}
	return nil
}

// validMapping rejects answers that cannot be a peer's target.
func validMapping(external netip.AddrPort, lifetime uint32) error {
	if !external.Addr().Is4() || external.Addr().IsUnspecified() || external.Port() == 0 {
		return fmt.Errorf("gateway assigned an unusable external address %s", external)
	}
	if lifetime == 0 {
		return errors.New("gateway granted a zero lifetime")
	}
	return nil
}
