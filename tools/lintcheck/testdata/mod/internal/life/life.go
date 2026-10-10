// Package life stands in for the real internal/life.
package life

import "context"

// Group runs goroutines.
type Group struct{ ctx context.Context }

// Go is the one place allowed to start goroutines.
func (g *Group) Go(name string, fn func(ctx context.Context)) bool {
	go fn(g.ctx)
	return true
}

// Close must not start goroutines.
func (g *Group) Close() {
	go func() {}() // want "nobarego"
}

// Go is a function, not the method.
func Go(fn func()) {
	go fn() // want "nobarego"
}

// Safe calls user code.
//
//holepunch:callback
func Safe(where string, fn func()) error {
	fn()
	return nil
}
