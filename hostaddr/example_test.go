package hostaddr_test

import (
	"context"
	"fmt"
	"time"

	"github.com/djylb/holepunch/hostaddr"
)

// Watch reports each change of the host's usable addresses — a new
// network, a lost interface — after which a peer-to-peer program looks for
// new paths. It blocks until ctx ends.
func ExampleWatch() {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	hostaddr.Watch(ctx, 0, func(now []hostaddr.Addr) {
		fmt.Println("network changed:", len(now), "usable addresses")
	})
}
