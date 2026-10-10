// Package proto is the signalling protocol of the standalone deployment: the
// messages a client and the standalone server exchange before, beside and
// instead of holepunch's own control protocol.
//
// # Streams
//
// Every client stream is a TLS connection to the server, and its first
// message says what the stream is for:
//
//   - Register opens a host's registration link. The server answers
//     Registered and then sends Incoming whenever a dialer opens a session
//     with the host; both sides send Heartbeat every Registered.HeartbeatMs,
//     and the host reports Transport outcomes on the link.
//   - Open asks for a session with a registered host. The server answers
//     SessionInfo, and holepunch's punch_start follows on the same stream: the
//     stream is now the dialer's control connection.
//   - Join takes up a session the host was told about in Incoming, with the
//     ticket it carried. The server answers SessionInfo and the stream
//     becomes the host's control connection.
//
// A refused request is answered with Fail, after which the server closes the
// stream.
//
// # Framing
//
// A frame is a 4-byte header — the protocol version (1), the message Type and
// the payload length as a big-endian uint16 — followed by a JSON payload of at
// most MaxPayload bytes. Decode reads exactly one frame and nothing more, so
// the bytes that follow SessionInfo stay on the stream for holepunch.
// Unknown JSON fields are ignored; a frame of another version or of an unknown
// type is an error, and so is any field that fails validation.
//
// # Concurrency and ownership
//
// The package is stateless. Its functions read or write the connection they
// are given and never close it; after an error the stream is out of step and
// the caller must close it.
package proto
