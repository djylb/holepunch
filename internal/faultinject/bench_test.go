package faultinject_test

import (
	"testing"

	"github.com/djylb/holepunch/internal/faultinject"
)

// BenchmarkPoint measures an unarmed point: in the default build it is
// inlined away and only the loop remains; in the tagged build it costs one
// registry lookup. A b.N loop is used on purpose: b.Loop keeps calls in its
// body from being inlined, which would hide exactly what is measured.
func BenchmarkPoint(b *testing.B) {
	for range b.N {
		if err := faultinject.Point("readloop.packet"); err != nil {
			b.Fatal(err)
		}
	}
}
