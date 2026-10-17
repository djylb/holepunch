package udpwire

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
)

// Domain-separation strings. "holepunch/1" is the
// protocol major version: changing it changes every derived key, which is how
// packets from another major version fail authentication.
const (
	labelAEAD  = "holepunch/1 udp aead"
	labelPacer = "holepunch/1 pacer"
	labelSpray = "holepunch/1 spray"
	labelMask  = "holepunch/1 route mask"
)

// hkdf32 is HKDF-SHA256 (RFC 5869) with IKM = token, salt = route and an
// output length of 32 bytes. One Expand block, T(1) = HMAC(PRK, info ‖ 0x01),
// is the whole output, so unlike crypto/hkdf there is no length to reject
// and no error path.
func hkdf32(token [32]byte, route [RouteSize]byte, info []byte) [32]byte {
	extract := hmac.New(sha256.New, route[:])
	extract.Write(token[:])
	expand := hmac.New(sha256.New, extract.Sum(nil))
	expand.Write(info)
	expand.Write([]byte{1})
	var okm [32]byte
	expand.Sum(okm[:0])
	return okm
}

// aeadKey derives the session's AES-256-GCM key.
func aeadKey(token [32]byte, route [RouteSize]byte) [32]byte {
	return hkdf32(token, route, []byte(labelAEAD))
}

// PacerSeed derives the 32-byte ChaCha8 seed of a sender's pacer stream:
// HKDF-SHA256(token, salt=route, info="holepunch/1 pacer" ‖ role). A Codec
// draws b0 and packet lengths from it. The client runtime does not draw from
// this stream: it hashes the seed with a label of its own into a separate
// jitter stream, so that no two consumers move in lockstep. Each role
// gets its own seed, so the two clients and natprobe never mirror one
// another.
func PacerSeed(token [32]byte, route [RouteSize]byte, role Role) [32]byte {
	return hkdf32(token, route, append([]byte(labelPacer), byte(role)))
}

// SpraySeed derives the 8-byte seed of a punch round's randomized target sets
// and orders (random-stage ports, predict-stage scatter, birthday targets,
// Direct repeat offsets): the first 8 bytes of HKDF-SHA256(token,
// salt=route, info="holepunch/1 spray" ‖ role ‖ round ‖ BE32(seed)), where seed
// is the round's RoundPlan.seed. Both clients can compute either side's seed,
// while different sessions and rounds always get different sets.
func SpraySeed(token [32]byte, route [RouteSize]byte, role Role, round uint8, seed uint32) [8]byte {
	info := append([]byte(labelSpray), byte(role), round)
	okm := hkdf32(token, route, binary.BigEndian.AppendUint32(info, seed))
	return [8]byte(okm[:8])
}

// routeMask returns SHA-256("holepunch/1 route mask" ‖ nonce); its first
// RouteSize bytes mask the route in envelope P. The mask is keyless: it only
// removes the constant prefix and gives no confidentiality.
func routeMask(nonce []byte) [sha256.Size]byte {
	var in [len(labelMask) + NonceSize]byte
	copy(in[:], labelMask)
	copy(in[len(labelMask):], nonce)
	return sha256.Sum256(in[:])
}
