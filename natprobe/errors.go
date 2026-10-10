package natprobe

import "errors"

// Errors of the registry and the server.
var (
	// ErrRegistryFull is returned when MaxEntries sessions are live, even
	// after dropping the target shard's expired entries.
	ErrRegistryFull = errors.New("natprobe: registry full")
	// ErrRouteInUse is returned when another live session holds the route;
	// the coordinator draws a new route.
	ErrRouteInUse = errors.New("natprobe: route registered by another session")
	// ErrConflict is returned when the session registered the route with
	// another token.
	ErrConflict = errors.New("natprobe: session re-registered with different token/route")
	// ErrCloseTimeout is returned when Close gave up joining the readers
	// after 2 s.
	ErrCloseTimeout = errors.New("natprobe: close timeout")
)
