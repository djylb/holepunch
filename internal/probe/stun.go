package probe

import (
	"encoding/binary"
	"net/netip"
)

// STUN (RFC 5389) Binding, the optional sub-probe. Only Binding Request and
// Success with (XOR-)MAPPED-ADDRESS are used; no OTHER-ADDRESS, no
// CHANGE-REQUEST.
const (
	stunMagic          = 0x2112A442
	stunHeaderSize     = 20
	stunBindingRequest = 0x0001
	stunBindingSuccess = 0x0101
	attrMappedAddress  = 0x0001
	attrXORMapped      = 0x0020
	maxSTUNMessage     = 1500
	stunFamilyV4       = 1
	stunFamilyV6       = 2
)

// IsSTUN reports whether pkt looks like a STUN message: first byte 0–3 and
// the magic cookie at offset 4. holepunch packets start with a byte in
// [0x04, 0x0F], so a read pump can tell the two apart from the first bytes
// alone.
func IsSTUN(pkt []byte) bool {
	return len(pkt) >= stunHeaderSize && pkt[0] < 4 && binary.BigEndian.Uint32(pkt[4:8]) == stunMagic
}

// appendSTUNRequest appends a Binding Request with transaction id txid.
func appendSTUNRequest(dst []byte, txid [12]byte) []byte {
	var h [stunHeaderSize]byte
	binary.BigEndian.PutUint16(h[0:], stunBindingRequest)
	binary.BigEndian.PutUint32(h[4:], stunMagic)
	copy(h[8:], txid[:])
	return append(dst, h[:]...)
}

// parseSTUN returns the transaction id and the mapped address of a Binding
// Success Response, preferring XOR-MAPPED-ADDRESS to MAPPED-ADDRESS.
func parseSTUN(pkt []byte) (txid [12]byte, mapped netip.AddrPort, ok bool) {
	if !IsSTUN(pkt) || binary.BigEndian.Uint16(pkt[0:]) != stunBindingSuccess {
		return txid, mapped, false
	}
	n := int(binary.BigEndian.Uint16(pkt[2:]))
	if n%4 != 0 || stunHeaderSize+n > len(pkt) || stunHeaderSize+n > maxSTUNMessage {
		return txid, mapped, false
	}
	copy(txid[:], pkt[8:20])
	var plain netip.AddrPort
	attrs := pkt[stunHeaderSize : stunHeaderSize+n]
	for len(attrs) >= 4 {
		typ := binary.BigEndian.Uint16(attrs[0:])
		l := int(binary.BigEndian.Uint16(attrs[2:]))
		padded := (l + 3) &^ 3
		if 4+padded > len(attrs) {
			return txid, mapped, false
		}
		v := attrs[4 : 4+l]
		switch typ {
		case attrXORMapped:
			if a, ok := stunAddress(v, true, txid); ok {
				return txid, a, true
			}
		case attrMappedAddress:
			if a, ok := stunAddress(v, false, txid); ok && !plain.IsValid() {
				plain = a
			}
		}
		attrs = attrs[4+padded:]
	}
	return txid, plain, plain.IsValid()
}

// stunAddress decodes a (XOR-)MAPPED-ADDRESS value.
func stunAddress(v []byte, xor bool, txid [12]byte) (netip.AddrPort, bool) {
	if len(v) < 4 {
		return netip.AddrPort{}, false
	}
	port := binary.BigEndian.Uint16(v[2:])
	var key [16]byte
	binary.BigEndian.PutUint32(key[:], stunMagic)
	copy(key[4:], txid[:])
	if xor {
		port ^= uint16(stunMagic >> 16)
	}
	var b [16]byte
	var ip netip.Addr
	switch {
	case v[1] == stunFamilyV4 && len(v) == 8:
		copy(b[:], v[4:8])
		xorKey(b[:4], key, xor)
		ip = netip.AddrFrom4([4]byte(b[:4]))
	case v[1] == stunFamilyV6 && len(v) == 20:
		copy(b[:], v[4:20])
		xorKey(b[:], key, xor)
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

// xorKey XORs b with the leading bytes of key (magic cookie ‖ transaction id)
// when xor is set.
func xorKey(b []byte, key [16]byte, xor bool) {
	if !xor {
		return
	}
	for i := range b {
		b[i] ^= key[i]
	}
}
