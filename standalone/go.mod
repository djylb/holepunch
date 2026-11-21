module github.com/djylb/holepunch/standalone

go 1.26.0

require (
	github.com/djylb/holepunch v0.0.0
	github.com/djylb/holepunch/quicpath v0.0.0
	github.com/quic-go/quic-go v0.65.0
)

require (
	github.com/djylb/timeshim v0.0.0-20261121052148-1ed9b7a27ad0 // indirect
	golang.org/x/crypto v0.59.0 // indirect
	golang.org/x/net v0.62.0 // indirect
	golang.org/x/sys v0.50.0 // indirect
)

replace (
	github.com/djylb/holepunch => ..
	github.com/djylb/holepunch/quicpath => ../quicpath
)
