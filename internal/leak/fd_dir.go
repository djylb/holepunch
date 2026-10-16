//go:build darwin || linux

package leak

import (
	"fmt"
	"os"
	"strconv"
	"syscall"
)

// OpenFDs returns the number of file descriptors open in this process.
func OpenFDs() (int, error) {
	names, err := listFDs()
	if err != nil {
		return 0, fmt.Errorf("leak: count file descriptors: %w", err)
	}
	// The listing includes the descriptors used to read it: one on linux,
	// two on darwin, where the directory is read through a duplicate. They
	// are closed by now, so only the descriptors still open are counted.
	n := 0
	var st syscall.Stat_t
	for _, name := range names {
		if fd, err := strconv.Atoi(name); err == nil && syscall.Fstat(fd, &st) == nil {
			n++
		}
	}
	return n, nil
}

// listFDs returns the names in fdDir and closes the directory again.
func listFDs() ([]string, error) {
	d, err := os.Open(fdDir)
	if err != nil {
		return nil, err
	}
	defer func() { _ = d.Close() }() // read-only: nothing is lost if closing fails
	return d.Readdirnames(-1)
}
