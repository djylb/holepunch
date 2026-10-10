package protocol

import "github.com/djylb/holepunch/controlwire"

// Feature is an optional client behaviour offered in punch_start.control and
// echoed (accepted subset) in probe_report.control. Syntax
// [a-z][a-z0-9_]{0,31}; at most 16 per message; unknown names are ignored.
type Feature string

// FeatureSandwich is the only feature: an experimental
// capability the operator may enable. Multiple rounds (preemption, rescue
// round), peer_seen assists, RTT alignment, server plans, ping/pong,
// round_result/punch_result and handover_ack are behaviour every
// implementation has, not features.
const FeatureSandwich Feature = "sandwich" // execute FamilySide.sandwich

// Valid reports whether f has the feature-name syntax [a-z][a-z0-9_]{0,31}.
func (f Feature) Valid() bool { return isName(string(f), maxFeatureName) }

// ControlSpec appears in punch_start.control (server offer) and
// probe_report.control (client echo of the accepted subset). There is no
// version range: Version must equal the frame header major exactly.
type ControlSpec struct {
	Version  uint8     `json:"version"`            // = controlwire.Version
	Features []Feature `json:"features,omitempty"` // server: offered; client: accepted
}

// DefaultControlSpec is what a server offers: version controlwire.Version and
// every supported feature.
func DefaultControlSpec() ControlSpec {
	return ControlSpec{Version: controlwire.Version, Features: SupportedFeatures()}
}

// SupportedFeatures are the features this implementation understands.
func SupportedFeatures() []Feature {
	return []Feature{FeatureSandwich}
}

// AcceptFeatures is the client's echo: offered ∩ supported, exact match,
// duplicates removed, in offer order.
func AcceptFeatures(offered, supported []Feature) []Feature {
	var out []Feature
	for _, f := range offered {
		if containsFeature(supported, f) && !containsFeature(out, f) {
			out = append(out, f)
		}
	}
	return out
}

// Has reports whether c lists f.
func (c ControlSpec) Has(f Feature) bool { return containsFeature(c.Features, f) }

func containsFeature(list []Feature, f Feature) bool {
	for _, x := range list {
		if x == f {
			return true
		}
	}
	return false
}
