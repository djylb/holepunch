// Command holepunchd is the standalone holepunch server: the TLS control
// listener (package server), the host registry and matchmaker with its
// coordinator (package broker), and the natprobe observers the clients probe
// their NATs against, all in one process, since the coordinator and natprobe
// share the session registry in memory.
//
// Usage:
//
//	holepunchd -probe-ip 203.0.113.5 [-probe-ip 2001:db8::5] [-listen :4343]
//	           [-cert cert.pem -key key.pem] [-auth-token SECRET] [-debug]
//
// -probe-ip binds a natprobe observer group to a public address; behind a
// 1:1 NAT (a cloud VM) write BIND=ADVERTISE, e.g. 10.0.0.5=203.0.113.5.
// -probe-alt-ip adds a second public IP for change-IP replies. Without
// -cert/-key the server makes a self-signed certificate at every start and
// logs its pin for the clients' -pin; a certificate of your own keeps the pin
// stable. SIGINT or SIGTERM shuts the server down.
package main
