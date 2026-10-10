package leak

import (
	"context"
	"fmt"
	"time"
)

// fdPollInterval is how often CheckFDs recounts. Descriptors can outlive
// Close briefly while the runtime finishes an in-flight read on them.
const fdPollInterval = 5 * time.Millisecond

// CheckFDs returns nil once the process has at most baseline open file
// descriptors, and an error with the last count when ctx ends first. The
// baseline is an earlier OpenFDs result, taken after the process has used
// the network once: the runtime's poller descriptors are created lazily on
// first use and then kept.
func CheckFDs(ctx context.Context, baseline int) error {
	t := time.NewTimer(0)
	defer t.Stop()
	for {
		n, err := OpenFDs()
		if err != nil {
			return err
		}
		if n <= baseline {
			return nil
		}
		t.Reset(fdPollInterval)
		select {
		case <-t.C:
		case <-ctx.Done():
			return fmt.Errorf("leak: %d file descriptors open, baseline %d: %w", n, baseline, context.Cause(ctx))
		}
	}
}
