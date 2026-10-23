// Package controlwire carries holepunch control frames over a reliable,
// encrypted and authenticated stream.
//
// # Frames
//
// A frame is an 8-byte header — 'h' 'p', major version 1, type, payload
// length as a big-endian uint32 — followed by the payload (a JSON object,
// decoded by package protocol). The twelve version-1 types, their payload
// caps, the side that sends each one and its write priority come from the
// type table of internal/wiretype, which package protocol shares. A header
// is validated before its
// payload is read or allocated: an oversized frame costs eight bytes of
// reading and no allocation.
//
// # Concurrency model
//
// A Conn owns exactly two goroutines, both started with life.Group.Go:
//
//   - ctl-read reads the connection: two Read calls per frame, never across a
//     frame boundary, no deadlines and no polling — an idle link is a single
//     blocked Read. Accepted frames go to Intercept and then to a bounded
//     inbox for ReadFrame. Reserved types and types sent in the wrong
//     direction are read (up to 4 KiB), dropped and counted; the 17th is a
//     protocol violation, as is the 513th frame of a link.
//   - ctl-write writes the connection: one frame at a time from four bounded
//     priority queues (P0 pong; P1 ping and reliable frames; P2 punch_assist, full
//     refuses; P3 punch_progress, full evicts the oldest), each frame under its
//     own write deadline (2 s for a client). Send, SendCoalesced and SendFunc
//     never block on the network; WriteFrame and Flush wait with a bound.
//
// A write that fails, times out or panics fails the write side: the stream
// may hold part of a frame, so nothing more is written, queued frames are
// dropped and every waiter is woken. Done and Err report the first failure of
// either direction.
//
// # Ownership
//
// The connection belongs to the caller. Release hands it back: it lets the
// frames in progress finish for at most 50 ms, interrupts what is still
// blocked — the read exactly once, through life.InterruptRead —
// joins both goroutines with a bound and clears both deadlines. After Release
// returns, the library starts no call on the connection; if the stream could
// not be handed back at a frame boundary Release says so (ErrUnreturnable)
// and the caller must close it. Close is the variant for owners of the
// connection, such as the coordinator: it closes it instead. Neither lets a
// panic of its own reach a caller or keep one waiting: the panic is the
// result, every caller gets it, and the Conn is stopped all the same. Every
// channel that signals an end is closed in a defer, or before anything that
// could fail, on the path that ends.
//
// The package depends on the standard library, internal/life and
// internal/faultinject (the ctl.read and ctl.write injection points, empty
// in production builds).
package controlwire
