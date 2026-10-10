// Package netaddr holds the address helpers of the holepunch client runtime:
// canonical forms of netip values, conversion from net.Addr, and the address
// classes that target admission rejects.
//
// Every function is pure: no I/O, no goroutines, no state. The package
// depends on the standard library only.
package netaddr
