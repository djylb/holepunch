//go:build !holepunch_faultinject

package faultinject

// Point marks the fault injection point with the given name. In this build
// it always returns nil and the compiler removes the call.
func Point(_ string) error { return nil }
