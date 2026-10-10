// Package testworld builds the standalone deployment inside a nattest
// network for the module's tests: natprobe observers, a broker with its
// coordinator and the TLS server on a public host, and clients behind
// simulated NATs whose control links are nattest pipes. It is test support
// only and never linked by a program.
//
// A World is used by one test; everything it creates is closed by the test's
// cleanup, after the clients the test created later.
package testworld
