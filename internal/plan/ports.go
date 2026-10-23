package plan

import "github.com/djylb/holepunch/internal/netaddr"

// Port filtering shared by every generated stage. The sensitive-UDP list is the
// one the previous implementation's portspray used, carried over verbatim.

// minUserPort is the lowest port a spray or predict stage may target; ports
// below it are only ever used when they are an observed peer mapping (exempt
// through the caller's allow set).
const minUserPort = netaddr.MinUserPort

// portRange is the width of [1024, 65535], the range a sequential
// allocator wraps around in.
const portRange = netaddr.PortRange

// SensitivePort reports whether p is on the fixed UDP avoid-list. A
// generated stage never targets such a port unless it is exactly an observed
// peer mapping.
func SensitivePort(p uint16) bool {
	switch p {
	case 0, 53, 67, 68, 69, 111, 123, 135, 137, 138, 139, 161, 162, 389, 427,
		500, 514, 520, 546, 547, 623, 631, 1434, 1900, 4500, 5353, 5355, 11211:
		return true
	default:
		return false
	}
}

// sensitiveUserPorts returns the entries of the avoid-list at or above
// minUserPort, the only ones a generated range can contain (SensitivePort is
// the definition; a test keeps the two in step).
func sensitiveUserPorts() [6]uint16 {
	return [6]uint16{1434, 1900, 4500, 5353, 5355, 11211}
}

// avoidPort reports whether a generated stage must skip p. allow is the set of
// ports exempt from the filter (observed peer mappings); it may be nil.
func avoidPort(p uint16, allow map[uint16]struct{}) bool {
	if _, ok := allow[p]; ok {
		return false
	}
	return p < minUserPort || SensitivePort(p)
}
