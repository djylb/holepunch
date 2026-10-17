package stun

// DefaultServers returns public STUN servers, as host:port: operators on
// several continents and networks, so that a client anywhere reaches some
// of them — the first ones are global anycast services, then servers
// reachable from mainland China, where the global ones may be blocked, and
// servers in Europe, Africa and North America. A client that asks several
// at once and takes the first answer loses nothing to one that is blocked
// or far away. Each call returns a new slice.
//
// For holepunch, natprobe.ResolveSTUN turns them into the addresses of
// protocol.ProbeSpec.STUN.
func DefaultServers() []string {
	return []string{
		"stun.cloudflare.com:3478",      // global anycast
		"stun.miwifi.com:3478",          // mainland China
		"stun.l.google.com:19302",       // global
		"stun.hitv.com:3478",            // mainland China
		"stun.nextcloud.com:3478",       // Europe
		"stun.syrex.co.za:3478",         // South Africa
		"stun.fbsbx.com:3478",           // global
		"stun.voip.blackberry.com:3478", // North America
		"stun1.l.google.com:19302",      // global
		"stun.t-online.de:3478",         // Europe
	}
}
