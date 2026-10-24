package natprobe

import (
	"net"

	"github.com/djylb/holepunch/protocol"
)

// SpecSource builds the ProbeSpecs of a long-running server from its parts,
// each read afresh at every call: the Server's live observers, the
// addresses of ServerAddrs (ProbeSpecAt) and the STUN servers of a
// STUNList. STUN and Addrs are optional. coord.ProbeFrom turns a SpecSource
// into a coord.ProbeFunc.
type SpecSource struct {
	Server *Server
	STUN   *STUNList
	Addrs  *ServerAddrs
}

// Spec returns the ProbeSpec for every session: the Server's at
// Addrs.Addrs, with the current STUN addresses.
func (s SpecSource) Spec() protocol.ProbeSpec {
	spec := s.Server.ProbeSpecAt(s.Addrs.Addrs()...)
	spec.STUN = s.STUN.Addrs()
	return spec
}

// SpecFor returns the ProbeSpec for the client on control
// (coord.AttachOptions.Probe): the Server's at Addrs.For(control), which
// puts the address that client connected to first, with the current STUN
// addresses.
func (s SpecSource) SpecFor(control net.Conn) protocol.ProbeSpec {
	spec := s.Server.ProbeSpecAt(s.Addrs.For(control)...)
	spec.STUN = s.STUN.Addrs()
	return spec
}
