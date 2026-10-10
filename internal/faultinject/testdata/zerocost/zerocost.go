// Package zerocost is compiled with -gcflags=-S by TestPointCompilesAway to
// show that an injection point, written the way the package documentation
// recommends, costs nothing in the default build.
package zerocost

import (
	"errors"
	"io"

	"github.com/djylb/holepunch/internal/faultinject"
)

// Hot is a hot path guarded by an injection point.
//
//goland:noinspection GoUnusedExportedFunction
func Hot(c io.Closer) error {
	if err := faultinject.Point("readloop.packet"); err != nil {
		if errors.Is(err, faultinject.ErrCloseConn) {
			_ = c.Close()
		}
		return err
	}
	return nil
}
