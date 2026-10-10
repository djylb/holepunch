//go:build !darwin && !linux

package leak

import "errors"

// OpenFDs returns the number of file descriptors open in this process. It is
// only implemented on darwin and linux and returns errors.ErrUnsupported
// elsewhere.
func OpenFDs() (int, error) { return 0, errors.ErrUnsupported }
