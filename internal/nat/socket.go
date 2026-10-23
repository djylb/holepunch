package nat

import (
	"net/netip"

	"github.com/djylb/holepunch/protocol"
)

// Socket indexes, the low seven bits of the header sock value
// sock = family<<7 | index.
// Indexes IndexFirstExtra–IndexLastExtra are assigned to round and birthday
// sockets in creation order.
const (
	IndexPrimary    uint8 = 0   // one per family; decides the family's traits
	IndexSecond     uint8 = 1   // opened when the primary looks APDM
	IndexSibling    uint8 = 2   // siblings use 2 and 3
	IndexSandwich   uint8 = 4   // the sandwich helper socket of a punching round
	IndexFirstExtra uint8 = 5   // the first round or birthday socket
	IndexLastExtra  uint8 = 125 // the last index left to round sockets
)

// SocketID returns the header sock value of socket index i of family f:
// bit 7 is 0 for udp4 and 1 for udp6, bits 0–6 hold the index.
func SocketID(f protocol.Family, i uint8) uint8 {
	id := i & 0x7F
	if f == protocol.FamilyUDP6 {
		id |= 0x80
	}
	return id
}

// SocketFamily returns the family encoded in bit 7 of a sock value.
func SocketFamily(sock uint8) protocol.Family {
	if sock&0x80 != 0 {
		return protocol.FamilyUDP6
	}
	return protocol.FamilyUDP4
}

// SocketMeta describes one probed socket.
type SocketMeta struct {
	ID    uint8               // sock = family<<7 | index
	Kind  protocol.SocketKind // primary, second or sibling
	Local netip.AddrPort      // concrete local address (wildcards expanded)
}

// validKind reports whether k is one of the three probing kinds.
func validKind(k protocol.SocketKind) bool {
	switch k {
	case protocol.SocketPrimary, protocol.SocketSecond, protocol.SocketSibling:
		return true
	}
	return false
}
