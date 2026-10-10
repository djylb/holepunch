package mod

import "time"

// A file for one operating system is production code.
func windowsOnly() {
	time.Sleep(1) // want "nosleep"
}
