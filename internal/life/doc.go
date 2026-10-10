// Package life is the single place where holepunch starts goroutines,
// recovers panics and interrupts blocked reads on connections it does not own.
//
// It provides three things:
//
//   - Group: a resource group that owns io.Closers and managed goroutines.
//     Every goroutine in the module is started with Group.Go, which recovers
//     panics into *PanicError and fails the group instead of crashing the
//     process. Close cancels the group, closes owned resources in reverse
//     order and joins the goroutines with a bound.
//   - Safe: a recover boundary for user callbacks, user implementations of
//     interfaces and individual cleanup steps.
//   - InterruptRead: the only implementation of "interrupt a blocked read
//     when a context ends" on a connection that belongs to the caller.
//
// # Concurrency
//
// All Group methods are safe for concurrent use. Close is idempotent; every
// caller waits for the first one to finish and receives the same error.
// Close must not be called synchronously from a goroutine of the same group:
// the join would wait for the caller itself until the join bound expires.
//
// # Ownership
//
// A resource handed to Own belongs to the group until Disown removes it or
// Close closes it. Own after Close closes the resource immediately, so a
// resource created concurrently with shutdown cannot leak.
//
// Text produced by this package (Error strings, formatted values) never
// contains stack traces; the stack of a recovered panic is only available
// through PanicError.Stack, for local logs.
//
// The package depends on the standard library only.
package life
