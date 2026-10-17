// Package stun encodes and decodes the STUN Binding messages of RFC 8489
// that discover a socket's public mapping, and asks a STUN server for it.
//
// It covers what NAT traversal needs and nothing more: Binding Requests,
// Binding Success Responses with XOR-MAPPED-ADDRESS (MAPPED-ADDRESS is
// accepted as well, for RFC 3489 servers), and a header check that tells a
// STUN message from other traffic on the same socket (RFC 7983). There is
// no authentication, no FINGERPRINT check and no TCP.
//
// Query is a complete client on a caller's socket, Serve a complete server,
// and DefaultServers lists public servers on several continents.
//
// The package depends on the standard library only, starts no goroutine
// and keeps no state.
package stun

import (
	"crypto/rand"
	"encoding/binary"
	"net/netip"
)

// Message constants (RFC 8489, sections 5 and 14).
const (
	// MagicCookie is the fixed value at offset 4 of every STUN message.
	MagicCookie uint32 = 0x2112A442
	// HeaderSize is the size of the STUN header.
	HeaderSize = 20
)

// Message types and attributes used here.
const (
	typeBindingRequest = 0x0001
	typeBindingSuccess = 0x0101
	attrMappedAddress  = 0x0001
	attrXORMapped      = 0x0020
	familyV4           = 1
	familyV6           = 2
	maxMessage         = 1500
)

// TransactionID is the 96-bit id that pairs a response with its request.
type TransactionID [12]byte

// NewTransactionID returns a random transaction id.
func NewTransactionID() TransactionID {
	var id TransactionID
	_, _ = rand.Read(id[:]) // crypto/rand.Read never fails
	return id
}

// IsMessage reports whether b is a STUN message by its header, the way a
// protocol classifier recognises one: the two top bits clear, the magic
// cookie at offset 4 and a message length that covers the rest of b in
// whole 32-bit words.
func IsMessage(b []byte) bool {
	if len(b) < HeaderSize || b[0]&0xC0 != 0 || binary.BigEndian.Uint32(b[4:]) != MagicCookie {
		return false
	}
	n := int(binary.BigEndian.Uint16(b[2:]))
	return n%4 == 0 && HeaderSize+n == len(b)
}

// AppendBindingRequest appends a Binding Request with transaction id id
// and no attributes to dst.
func AppendBindingRequest(dst []byte, id TransactionID) []byte {
	return appendHeader(dst, typeBindingRequest, 0, id)
}

// ParseBindingRequest returns the transaction id of a Binding Request. Its
// attributes, if any, are not examined.
func ParseBindingRequest(b []byte) (TransactionID, bool) {
	if !IsMessage(b) || binary.BigEndian.Uint16(b) != typeBindingRequest {
		return TransactionID{}, false
	}
	return TransactionID(b[8:HeaderSize]), true
}

// AppendBindingResponse appends to dst the Binding Success Response to the
// request id that reports mapped, the request's source address, in an
// XOR-MAPPED-ADDRESS attribute. An IPv4-mapped IPv6 address is reported as
// IPv4; an invalid one gives a response without an address.
func AppendBindingResponse(dst []byte, id TransactionID, mapped netip.AddrPort) []byte {
	ip := mapped.Addr().Unmap()
	if !ip.IsValid() {
		return appendHeader(dst, typeBindingSuccess, 0, id)
	}
	size, fam := 8, byte(familyV4)
	if ip.Is6() {
		size, fam = 20, familyV6
	}
	dst = appendHeader(dst, typeBindingSuccess, 4+size, id)
	var a [24]byte
	binary.BigEndian.PutUint16(a[0:], attrXORMapped)
	binary.BigEndian.PutUint16(a[2:], uint16(size))
	a[5] = fam
	binary.BigEndian.PutUint16(a[6:], mapped.Port()^uint16(MagicCookie>>16))
	key := xorKey(id)
	if fam == familyV4 {
		b := ip.As4()
		copy(a[8:], b[:])
	} else {
		b := ip.As16()
		copy(a[8:], b[:])
	}
	for i := range size - 4 {
		a[8+i] ^= key[i]
	}
	return append(dst, a[:4+size]...)
}

// ParseBindingResponse returns the transaction id of a Binding Success
// Response and the mapped address it reports, from XOR-MAPPED-ADDRESS or,
// without one, MAPPED-ADDRESS. ok is false for any other message, and for a
// response without a usable address (port 0, unspecified IP). Bytes after
// the message are ignored.
func ParseBindingResponse(b []byte) (id TransactionID, mapped netip.AddrPort, ok bool) {
	if len(b) < HeaderSize || b[0]&0xC0 != 0 || binary.BigEndian.Uint32(b[4:]) != MagicCookie ||
		binary.BigEndian.Uint16(b) != typeBindingSuccess {
		return id, mapped, false
	}
	n := int(binary.BigEndian.Uint16(b[2:]))
	if n%4 != 0 || HeaderSize+n > len(b) || HeaderSize+n > maxMessage {
		return id, mapped, false
	}
	id = TransactionID(b[8:HeaderSize])
	var plain netip.AddrPort
	attrs := b[HeaderSize : HeaderSize+n]
	for len(attrs) >= 4 {
		typ := binary.BigEndian.Uint16(attrs[0:])
		l := int(binary.BigEndian.Uint16(attrs[2:]))
		padded := (l + 3) &^ 3
		if 4+padded > len(attrs) {
			return id, netip.AddrPort{}, false
		}
		v := attrs[4 : 4+l]
		switch typ {
		case attrXORMapped:
			if a, ok := decodeAddress(v, true, id); ok {
				return id, a, true
			}
		case attrMappedAddress:
			if a, ok := decodeAddress(v, false, id); ok && !plain.IsValid() {
				plain = a
			}
		}
		attrs = attrs[4+padded:]
	}
	return id, plain, plain.IsValid()
}

func appendHeader(dst []byte, typ uint16, length int, id TransactionID) []byte {
	var h [HeaderSize]byte
	binary.BigEndian.PutUint16(h[0:], typ)
	binary.BigEndian.PutUint16(h[2:], uint16(length))
	binary.BigEndian.PutUint32(h[4:], MagicCookie)
	copy(h[8:], id[:])
	return append(dst, h[:]...)
}

// xorKey is the XOR key of an address: the magic cookie, then the
// transaction id.
func xorKey(id TransactionID) [16]byte {
	var key [16]byte
	binary.BigEndian.PutUint32(key[:], MagicCookie)
	copy(key[4:], id[:])
	return key
}

// decodeAddress decodes a (XOR-)MAPPED-ADDRESS value.
func decodeAddress(v []byte, xor bool, id TransactionID) (netip.AddrPort, bool) {
	if len(v) < 4 {
		return netip.AddrPort{}, false
	}
	port := binary.BigEndian.Uint16(v[2:])
	var key [16]byte
	if xor {
		port ^= uint16(MagicCookie >> 16)
		key = xorKey(id)
	}
	var b [16]byte
	var ip netip.Addr
	switch {
	case v[1] == familyV4 && len(v) == 8:
		for i := range 4 {
			b[i] = v[4+i] ^ key[i]
		}
		ip = netip.AddrFrom4([4]byte(b[:4]))
	case v[1] == familyV6 && len(v) == 20:
		for i := range 16 {
			b[i] = v[4+i] ^ key[i]
		}
		ip = netip.AddrFrom16(b)
	default:
		return netip.AddrPort{}, false
	}
	// An IPv4-mapped IPv6 value is the IPv4 address: unmap before the
	// check, or ::ffff:0.0.0.0 would pass as a usable address.
	ip = ip.Unmap()
	if port == 0 || ip.IsUnspecified() {
		return netip.AddrPort{}, false
	}
	return netip.AddrPortFrom(ip, port), true
}
