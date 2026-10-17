#!/usr/bin/env python3
"""Generates controlwire/testdata/frames.json, independently of the Go code.

Written from the control frame format: a frame is 'h' 'p' major type
len(BE32) payload; major is 1; types 1..12 are numbered contiguously;
13..255 are reserved and, like types sent in the wrong direction, are read
(cap 4 KiB), dropped and counted, the 17th being a violation; the 513th
frame of a link is a violation.

Usage: python3 gen_vectors.py frames.json
"""
import json
import struct
import sys

MAJOR = 1
# name -> (number, sender, cap, write priority)
TYPES = {
    "punch_start":    (1, "server", 16 << 10, 1),
    "probe_report":   (2, "client", 32 << 10, 1),
    "probe_summary":  (3, "server", 48 << 10, 1),
    "punch_ready":    (4, "client", 1 << 10, 1),
    "punch_go":       (5, "server", 8 << 10, 1),
    "punch_progress": (6, "client", 2 << 10, 3),
    "punch_assist":   (7, "both", 1 << 10, 2),
    "punch_abort":    (8, "server", 1 << 10, 1),
    "ping":           (9, "server", 256, 1),
    "pong":           (10, "client", 256, 0),
    "round_result":   (11, "client", 4 << 10, 1),
    "punch_result":   (12, "client", 8 << 10, 1),
}
T = {name: v[0] for name, v in TYPES.items()}
FIRST_RESERVED = max(T.values()) + 1
assert sorted(T.values()) == list(range(1, FIRST_RESERVED)), "numbering must be contiguous"
DISCARD_CAP = 4 << 10
GLOBAL_MAX = 64 << 10
MAX_DISCARDED = 16
MAX_FRAMES = 512


def frame(typ, payload=b"", major=MAJOR, length=None, magic=b"hp"):
    if isinstance(payload, str):
        payload = payload.encode()
    n = len(payload) if length is None else length
    return magic + bytes([major, typ]) + struct.pack(">I", n) + payload


def header(typ, length, major=MAJOR):
    return frame(typ, b"", major, length)


encode = []


def add_encode(name, typ, payload):
    encode.append({"name": name, "type": typ, "payload": payload, "hex": frame(typ, payload).hex()})


add_encode("punch_start_min", T["punch_start"], "{}")
add_encode("ping", T["ping"], '{"seq":1}')
add_encode("pong", T["pong"], '{"seq":2,"hold_us":41,"client_unix_ms":1791234567514}')
add_encode("punch_go_empty_payload", T["punch_go"], "")
add_encode("punch_result", T["punch_result"], '{"ok":true}')
add_encode("reserved_type_13", FIRST_RESERVED, "x")

decode = []


def add_decode(name, side, data, frames, err, discarded):
    decode.append({"name": name, "side": side, "hex": data.hex(),
                   "frames": [{"type": t, "payload": p} for t, p in frames],
                   "err": err, "discarded": discarded})


ping = '{"seq":1}'
add_decode("ping_then_eof", "client", frame(T["ping"], ping), [(T["ping"], ping)], "EOF", 0)
add_decode("zero_length_payload", "client", frame(T["punch_go"], ""), [(T["punch_go"], "")], "EOF", 0)
add_decode("major_0", "client", frame(T["punch_start"], "{}", major=0), [], "ErrVersion", 0)
add_decode("major_2", "client", frame(T["punch_start"], "{}", major=2), [], "ErrVersion", 0)
add_decode("bad_magic", "client", frame(T["ping"], "", magic=b"HP"), [], "ErrBadMagic", 0)
add_decode("zero_type", "client", frame(0, ""), [], "ErrZeroType", 0)
add_decode("start_over_cap", "client", header(T["punch_start"], (16 << 10) + 1), [], "ErrFrameTooLarge", 0)
add_decode("start_at_cap_truncated", "client", header(T["punch_start"], 16 << 10) + b"{", [], "ErrUnexpectedEOF", 0)
add_decode("header_truncated", "client", frame(T["ping"], ping)[:5], [], "ErrUnexpectedEOF", 0)
add_decode("summary_over_global", "client", header(T["probe_summary"], GLOBAL_MAX + 1), [], "ErrFrameTooLarge", 0)
add_decode("summary_over_cap", "client", header(T["probe_summary"], (48 << 10) + 1), [], "ErrFrameTooLarge", 0)
add_decode("ping_over_cap", "client", header(T["ping"], 257), [], "ErrFrameTooLarge", 0)
add_decode("first_reserved_discarded", "client",
           frame(FIRST_RESERVED, '{"x":1}') + frame(T["ping"], ping), [(T["ping"], ping)], "EOF", 1)
add_decode("reserved_200_discarded", "client",
           frame(200, "abc") + frame(T["punch_go"], "{}"), [(T["punch_go"], "{}")], "EOF", 1)
add_decode("reserved_255_discarded", "server",
           frame(255, "") + frame(T["pong"], "{}"), [(T["pong"], "{}")], "EOF", 1)
add_decode("reserved_at_discard_cap", "client", frame(200, "x" * DISCARD_CAP), [], "EOF", 1)
add_decode("reserved_over_discard_cap", "client", header(200, DISCARD_CAP + 1), [], "ErrFrameTooLarge", 0)
add_decode("wrong_direction_discarded_client", "client",
           frame(T["probe_report"], '{"role":"x"}') + frame(T["pong"], "{}") + frame(T["punch_result"], "{}"),
           [], "EOF", 3)
add_decode("wrong_direction_discarded_server", "server",
           frame(T["punch_start"], "{}") + frame(T["probe_summary"], "{}") + frame(T["punch_go"], "{}") +
           frame(T["ping"], ping), [], "EOF", 4)
add_decode("wrong_direction_uses_discard_cap", "server",
           header(T["probe_summary"], DISCARD_CAP + 1), [], "ErrFrameTooLarge", 0)
# A client's punch_abort is a wrong-direction frame like any other.
add_decode("client_abort_discarded_by_server", "server",
           frame(T["punch_abort"], '{"code":"internal"}') + frame(T["round_result"], "{}"),
           [(T["round_result"], "{}")], "EOF", 1)
add_decode("assist_both_ways_client", "client", frame(T["punch_assist"], "{}"),
           [(T["punch_assist"], "{}")], "EOF", 0)
add_decode("assist_both_ways_server", "server", frame(T["punch_assist"], "{}"),
           [(T["punch_assist"], "{}")], "EOF", 0)
add_decode("sixteen_discarded_ok", "client", frame(FIRST_RESERVED, "") * MAX_DISCARDED, [], "EOF", MAX_DISCARDED)
add_decode("seventeen_discarded_violation", "client",
           frame(FIRST_RESERVED, "") * (MAX_DISCARDED + 1), [], "ErrTooManyUnknown", MAX_DISCARDED + 1)
add_decode("seventeen_wrong_direction_violation", "server",
           frame(T["punch_abort"], "{}") * (MAX_DISCARDED + 1), [], "ErrTooManyUnknown", MAX_DISCARDED + 1)
add_decode("frame_513_flood", "server", frame(T["pong"], "{}") * (MAX_FRAMES + 1),
           [(T["pong"], "{}")] * MAX_FRAMES, "ErrFlood", 0)

out = {
    "comment": "controlwire frame vectors. "
               "Generated by gen_vectors.py independently of the Go code; hex is the exact byte stream.",
    "types": {name: {"type": v[0], "sender": v[1], "cap": v[2], "priority": v[3]} for name, v in TYPES.items()},
    "discard_cap": DISCARD_CAP,
    "max_payload": GLOBAL_MAX,
    "encode": encode,
    "decode": decode,
}
with open(sys.argv[1], "w") as f:
    json.dump(out, f, indent=1, ensure_ascii=True)
    f.write("\n")
