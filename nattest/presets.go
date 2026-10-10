package nattest

import (
	"net/netip"
	"strconv"
)

// The presets are common NAT behaviours and the test profiles built on
// them. They are IPv4 only; set
// NATConfig.IPv6 for dual stack. Each returns a fresh value the caller may
// modify.

// PublicOpen is a host with a public address and no firewall (PUB).
func PublicOpen() NATConfig {
	return NATConfig{Name: "PUB", Mapping: Identity, Filtering: Open}
}

// PublicFW is a host with a public address behind a stateful firewall that
// filters by address and port (PUBFW).
func PublicFW() NATConfig {
	return NATConfig{Name: "PUBFW", Mapping: Identity, Filtering: APDF}
}

// FullCone is EIM + EIF with port preservation (FC).
func FullCone() NATConfig {
	return NATConfig{Name: "FC", Mapping: EIM, Filtering: EIF}
}

// RestrictedCone is EIM + ADF with port preservation (RC).
func RestrictedCone() NATConfig {
	return NATConfig{Name: "RC", Mapping: EIM, Filtering: ADF}
}

// PortRestricted is EIM + APDF with port preservation (PRC).
func PortRestricted() NATConfig {
	return NATConfig{Name: "PRC", Mapping: EIM, Filtering: APDF}
}

// SymmetricSeq is APDM + APDF with sequential allocation in steps of step
// (SYMSEQ; SYMSEQ2 with step 2, SYMSEQ-1 counting down).
func SymmetricSeq(step int) NATConfig {
	name := "SYMSEQ"
	if step != 1 {
		name += strconv.Itoa(step)
	}
	return NATConfig{Name: name, Mapping: APDM, Filtering: APDF, PortAlloc: Sequential, PortStep: step}
}

// SymmetricPreserveRandom is APDM + APDF that keeps the internal port when
// it is free and picks a random one otherwise (PRESRND): a fresh socket's
// first mapping keeps its port, its later ones are random.
func SymmetricPreserveRandom() NATConfig {
	return NATConfig{Name: "PRESRND", Mapping: APDM, Filtering: APDF, PortAlloc: PreserveThenRandom}
}

// SymmetricRandom is APDM + APDF with random allocation (SYMRND).
func SymmetricRandom() NATConfig {
	return NATConfig{Name: "SYMRND", Mapping: APDM, Filtering: APDF, PortAlloc: Random}
}

// CGNAT returns the carrier (outer) and home (inner) configurations of a
// two-level NAT, to be attached as n.NAT(c[0]).NAT(c[1]). The carrier's LAN
// defaults to the shared address space 100.64.0.0/10 and its name to "CGNAT".
func CGNAT(outer, inner NATConfig) [2]NATConfig {
	if !outer.LANPrefix.IsValid() {
		outer.LANPrefix = netip.PrefixFrom(netip.AddrFrom4([4]byte{100, 64, 0, 0}), 10)
	}
	if outer.Name == "" {
		outer.Name = "CGNAT"
	}
	return [2]NATConfig{outer, inner}
}
