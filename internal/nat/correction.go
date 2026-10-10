package nat

import "github.com/djylb/holepunch/protocol"

// Correction returns the punch-time correction from prev, the traits this side
// was planned with (normally its probe_summary self view), to cur, the
// reclassified table, for punch_result.traits. Only fields that changed are
// set; ok is false when nothing changed.
func Correction(prev, cur protocol.Traits, source protocol.TraitsSource) (u protocol.TraitsUpdate, ok bool) {
	u = protocol.TraitsUpdate{Family: cur.Family, Source: source}
	u.Mapping = changed(prev.Mapping, cur.Mapping, &ok)
	u.MappingConf = changed(prev.MappingConf, cur.MappingConf, &ok)
	u.Filtering = changed(prev.Filtering, cur.Filtering, &ok)
	u.FilteringConf = changed(prev.FilteringConf, cur.FilteringConf, &ok)
	u.PortStep = changed(prev.PortStep, cur.PortStep, &ok)
	u.PortVelocity = changed(prev.PortVelocity, cur.PortVelocity, &ok)
	u.Hairpin = changed(prev.Hairpin, cur.Hairpin, &ok)
	return u, ok
}

// changed returns a pointer to cur when it differs from prev, recording the
// change in *diff, and nil otherwise.
func changed[T comparable](prev, cur T, diff *bool) *T {
	if prev == cur {
		return nil
	}
	*diff = true
	return &cur
}
