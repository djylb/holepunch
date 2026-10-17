package stun_test

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/djylb/holepunch/stun"
)

// Query asks a public STUN server for this socket's public address.
func ExampleQuery() {
	conn, err := net.ListenPacket("udp4", ":0")
	if err != nil {
		return
	}
	defer func() { _ = conn.Close() }()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	for _, s := range stun.DefaultServers() {
		ua, err := net.ResolveUDPAddr("udp4", s)
		if err != nil {
			continue
		}
		if mapped, err := stun.Query(ctx, conn, ua.AddrPort()); err == nil {
			fmt.Println("public address:", mapped)
			return
		}
	}
}
