// Package testkit holds the helpers the module's tests share: bounded
// polling waits that scale with the test binary's deadline, the race
// detector flag, and clocks that misbehave on purpose. It is test support
// only, never imported by library code, and depends on the standard library
// and package clock only.
package testkit
