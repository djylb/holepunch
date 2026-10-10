//go:build !holepunch_faultinject

package mod

import "time"

func inert() {
	time.Sleep(1) // want "nosleep"
}
