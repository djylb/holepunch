//go:build !holepunch_faultinject

package faultinject_test

import (
	"testing"

	"github.com/djylb/holepunch/internal/faultinject"
)

func TestPointIsInertWithoutTag(t *testing.T) {
	for _, name := range []string{"probe.bind", "coord.finish.notify", "not a point name", ""} {
		if err := faultinject.Point(name); err != nil {
			t.Fatalf("Point(%q) = %v in the default build", name, err)
		}
	}
	if n := testing.AllocsPerRun(100, func() { _ = faultinject.Point("readloop.packet") }); n != 0 {
		t.Fatalf("Point allocates %v times per call", n)
	}
}
