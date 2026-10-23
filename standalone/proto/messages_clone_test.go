package proto

import "testing"

// Clone copies the maps and the policy: changing the copy leaves the
// original alone, and cloning changes nothing.
func TestSessionInfoClone(t *testing.T) {
	orig := SessionInfo{HostMetadata: map[string]string{"a": "1"}, DialerMetadata: map[string]string{"b": "2"},
		Policy: AccessPolicy{Targets: []string{"x:1"}}}
	c := orig.Clone()
	c.HostMetadata["a"], c.DialerMetadata["b"], c.Policy.Targets[0] = "9", "9", "y:2"
	if orig.HostMetadata["a"] != "1" || orig.DialerMetadata["b"] != "2" || orig.Policy.Targets[0] != "x:1" {
		t.Fatalf("the original changed: %+v", orig)
	}
}
