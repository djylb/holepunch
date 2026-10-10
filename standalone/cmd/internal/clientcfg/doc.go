// Package clientcfg holds the flags the client commands (holepunch,
// holepunch-diag) share and turns them into a client.Config: the server
// address and token, how the server's certificate is verified (pin, CA file
// or system roots), the local address and the optional port mapper.
//
// It is stateless; Flags.Config returns the port mapper it may create with
// its cleanup, which the command runs before it exits.
package clientcfg
