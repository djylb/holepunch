//go:build darwin || linux

package leak

import (
	"fmt"
	"os"
)

// OpenFDs returns the number of file descriptors open in this process.
func OpenFDs() (int, error) {
	d, err := os.Open(fdDir)
	if err != nil {
		return 0, fmt.Errorf("leak: count file descriptors: %w", err)
	}
	defer func() { _ = d.Close() }() // read-only: nothing is lost if closing fails
	names, err := d.Readdirnames(-1)
	if err != nil {
		return 0, fmt.Errorf("leak: count file descriptors: %w", err)
	}
	// The directory itself is listed through the descriptor used to read it.
	return len(names) - 1, nil
}
