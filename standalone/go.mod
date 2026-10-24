module github.com/djylb/holepunch/standalone

go 1.26.0

require (
	github.com/djylb/holepunch v0.0.0
	github.com/djylb/holepunch/quicpath v0.0.0
	github.com/quic-go/quic-go v0.63.0
	go.uber.org/goleak v1.3.0
)

require (
	github.com/huin/goupnp v1.3.0 // indirect
	golang.org/x/crypto v0.58.0 // indirect
	golang.org/x/net v0.61.0 // indirect
	golang.org/x/sync v0.24.0 // indirect
	golang.org/x/sys v0.49.0 // indirect
)

replace (
	github.com/djylb/holepunch => ..
	github.com/djylb/holepunch/quicpath => ../quicpath
)
