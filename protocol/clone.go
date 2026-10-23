package protocol

import (
	"maps"
	"slices"
)

// Deep copies of the structures a session hands out or keeps beyond the
// call that produced them. Each Clone shares no pointer, slice or map with
// its receiver, so either may be written without affecting the other; nil
// stays nil and an empty slice or map stays empty.

// Clone returns a deep copy of p.
func (p Policy) Clone() Policy {
	p.PortMapping = p.PortMapping.Clone()
	p.LowTTL = cloneBool(p.LowTTL)
	p.LowTTLHops = slices.Clone(p.LowTTLHops)
	return p
}

// Clone returns a deep copy of p.
func (p PortMappingPolicy) Clone() PortMappingPolicy {
	p.EnableUPnP = cloneBool(p.EnableUPnP)
	p.EnablePCP = cloneBool(p.EnablePCP)
	p.EnableNATPMP = cloneBool(p.EnableNATPMP)
	return p
}

func cloneBool(b *bool) *bool {
	if b == nil {
		return nil
	}
	v := *b
	return &v
}

// Clone returns a deep copy of c.
func (c ControlSpec) Clone() ControlSpec {
	c.Features = slices.Clone(c.Features)
	return c
}

// Clone returns a deep copy of p.
func (p ProbeSpec) Clone() ProbeSpec {
	p.Observers = slices.Clone(p.Observers)
	p.STUN = slices.Clone(p.STUN)
	return p
}

// Clone returns a deep copy of m.
func (m PunchStart) Clone() PunchStart {
	m.Control = m.Control.Clone()
	m.Probe = m.Probe.Clone()
	if m.Policy != nil {
		pol := m.Policy.Clone()
		m.Policy = &pol
	}
	return m
}

// Clone returns a deep copy of v.
func (v PeerView) Clone() PeerView {
	v.Families = slices.Clone(v.Families)
	for i := range v.Families {
		v.Families[i] = v.Families[i].Clone()
	}
	return v
}

// Clone returns a deep copy of v.
func (v FamilyView) Clone() FamilyView {
	v.Endpoints = slices.Clone(v.Endpoints)
	return v
}

// Clone returns a deep copy of p.
func (p PairFacts) Clone() PairFacts {
	p.SharedFamilies = slices.Clone(p.SharedFamilies)
	p.SamePublicIP = maps.Clone(p.SamePublicIP)
	p.LikelySameLAN = maps.Clone(p.LikelySameLAN)
	p.SharedOverlay = maps.Clone(p.SharedOverlay)
	p.ProbeRTTMs = maps.Clone(p.ProbeRTTMs)
	p.ClockOffsetMs = maps.Clone(p.ClockOffsetMs)
	p.Unverified = maps.Clone(p.Unverified)
	return p
}

// Clone returns a deep copy of p.
func (p PlanSpec) Clone() PlanSpec {
	p.Ladder = slices.Clone(p.Ladder)
	p.Round1 = p.Round1.Clone()
	return p
}

// Clone returns a deep copy of r, down to the stage targets.
func (r RoundPlan) Clone() RoundPlan {
	r.Sides = slices.Clone(r.Sides)
	for i := range r.Sides {
		r.Sides[i] = r.Sides[i].Clone()
	}
	return r
}

// Clone returns a deep copy of s.
func (s FamilySide) Clone() FamilySide {
	s.Stages = slices.Clone(s.Stages)
	for i := range s.Stages {
		s.Stages[i] = s.Stages[i].Clone()
	}
	return s
}

// Clone returns a deep copy of s.
func (s Stage) Clone() Stage {
	s.Targets = slices.Clone(s.Targets)
	s.Steps = slices.Clone(s.Steps)
	return s
}
