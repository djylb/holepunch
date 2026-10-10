// Package e2e is tests, not library: never reported.
package e2e

import "time"

var state int

func helper() {
	state++
	go helper()
	time.Sleep(1)
}
