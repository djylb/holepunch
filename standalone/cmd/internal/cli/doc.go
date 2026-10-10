// Package cli holds what every standalone command shares: repeatable flags,
// logging and signal handling. It depends on the standard library only, so
// that the server command links nothing of the client side.
//
// It is stateless.
package cli
