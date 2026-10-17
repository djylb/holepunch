#!/usr/bin/env python3
"""Independent generator for the udpwire test vectors.

This script shares no code with the Go package: it builds kdf.json and
wire/*.json from the protocol text alone, using only the Python standard
library (hmac/hashlib for HKDF and SHA-256, plus a from-scratch AES-256 and
GCM that self-test against FIPS-197 and the GCM specification before any file
is written). The Go tests then require udpwire to reproduce these bytes.

Usage: python3 -I gen_vectors.py [OUTPUT_DIR]   (default: this file's directory)
"""

import hashlib
import hmac
import ipaddress
import json
import os
import struct
import sys

# ---------------------------------------------------------------------------
# AES-256 (FIPS-197) and GCM (NIST SP 800-38D)
# ---------------------------------------------------------------------------


def gmul(a, b):
    p = 0
    for _ in range(8):
        if b & 1:
            p ^= a
        hi = a & 0x80
        a = (a << 1) & 0xFF
        if hi:
            a ^= 0x1B
        b >>= 1
    return p


def build_sbox():
    inv = [0] * 256
    for x in range(1, 256):
        for y in range(1, 256):
            if gmul(x, y) == 1:
                inv[x] = y
                break
    sbox = []
    for x in range(256):
        b = inv[x]
        s = b
        for i in range(1, 5):
            s ^= ((b << i) | (b >> (8 - i))) & 0xFF
        sbox.append(s ^ 0x63)
    return sbox


SBOX = build_sbox()


def expand_key(key):
    nk, nr = 8, 14
    w = [list(key[4 * i:4 * i + 4]) for i in range(nk)]
    rcon = 1
    for i in range(nk, 4 * (nr + 1)):
        t = list(w[i - 1])
        if i % nk == 0:
            t = t[1:] + t[:1]
            t = [SBOX[b] for b in t]
            t[0] ^= rcon
            rcon = gmul(rcon, 2)
        elif i % nk == 4:
            t = [SBOX[b] for b in t]
        w.append([a ^ b for a, b in zip(w[i - nk], t)])
    return [sum(w[4 * r:4 * r + 4], []) for r in range(nr + 1)]


def mix_columns(s):
    out = []
    for c in range(4):
        a = s[4 * c:4 * c + 4]
        out += [
            gmul(a[0], 2) ^ gmul(a[1], 3) ^ a[2] ^ a[3],
            a[0] ^ gmul(a[1], 2) ^ gmul(a[2], 3) ^ a[3],
            a[0] ^ a[1] ^ gmul(a[2], 2) ^ gmul(a[3], 3),
            gmul(a[0], 3) ^ a[1] ^ a[2] ^ gmul(a[3], 2),
        ]
    return out


def aes_encrypt(rk, block):
    s = [b ^ k for b, k in zip(block, rk[0])]
    for r in range(1, 15):
        s = [SBOX[b] for b in s]
        s = [s[(i + 4 * (i % 4)) % 16] for i in range(16)]  # ShiftRows (column-major state)
        if r != 14:
            s = mix_columns(s)
        s = [b ^ k for b, k in zip(s, rk[r])]
    return bytes(s)


GCM_R = 0xE1 << 120


def gf_mult(x, y):
    z, v = 0, y
    for i in range(127, -1, -1):
        if (x >> i) & 1:
            z ^= v
        v = (v >> 1) ^ GCM_R if v & 1 else v >> 1
    return z


def ghash(h, data):
    y = 0
    for i in range(0, len(data), 16):
        y = gf_mult(y ^ int.from_bytes(data[i:i + 16], "big"), h)
    return y


def pad16(b):
    return b + bytes(-len(b) % 16)


def gcm_seal(key, nonce, plaintext, aad):
    assert len(nonce) == 12
    rk = expand_key(key)
    h = int.from_bytes(aes_encrypt(rk, bytes(16)), "big")
    j0 = nonce + b"\x00\x00\x00\x01"
    ct = bytearray()
    ctr = int.from_bytes(j0[12:], "big")
    for i in range(0, len(plaintext), 16):
        ctr = (ctr + 1) & 0xFFFFFFFF
        ks = aes_encrypt(rk, nonce + ctr.to_bytes(4, "big"))
        chunk = plaintext[i:i + 16]
        ct += bytes(a ^ b for a, b in zip(chunk, ks))
    lens = struct.pack(">QQ", len(aad) * 8, len(ct) * 8)
    s = ghash(h, pad16(aad) + pad16(bytes(ct)) + lens)
    tag = (s ^ int.from_bytes(aes_encrypt(rk, j0), "big")).to_bytes(16, "big")
    return bytes(ct) + tag


def hkdf(ikm, salt, info, length):
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()
    okm, t, i = b"", b"", 1
    while len(okm) < length:
        t = hmac.new(prk, t + info + bytes([i]), hashlib.sha256).digest()
        okm += t
        i += 1
    return okm[:length]


def self_test():
    # FIPS-197 Appendix C.3 (AES-256).
    rk = expand_key(bytes(range(32)))
    assert aes_encrypt(rk, bytes.fromhex("00112233445566778899aabbccddeeff")).hex() == \
        "8ea2b7ca516745bfeafc49904b496089", "AES-256 FIPS-197 C.3"
    # GCM specification (McGrew/Viega) test cases 13 and 14 (AES-256).
    assert gcm_seal(bytes(32), bytes(12), b"", b"").hex() == \
        "530f8afbc74536b9a963b4f1c4cb738b", "GCM test case 13"
    assert gcm_seal(bytes(32), bytes(12), bytes(16), b"").hex() == \
        "cea7403d4d606b6e074ec5d3baf39d18" "d0d1c8a799996bf0265b98b5d48ab919", "GCM test case 14"
    # RFC 5869 A.1 (HKDF-SHA256).
    assert hkdf(bytes([0x0B] * 22), bytes(range(13)), bytes(range(0xF0, 0xFA)), 42).hex() == \
        "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865", \
        "RFC 5869 A.1"


# ---------------------------------------------------------------------------
# Protocol constants, transcribed from the UDP packet format
# ---------------------------------------------------------------------------

LABEL_AEAD = b"holepunch/1 udp aead"
LABEL_PACER = b"holepunch/1 pacer"
LABEL_SPRAY = b"holepunch/1 spray"
LABEL_MASK = b"holepunch/1 route mask"

TYPES = {
    "probe": 1, "probe_ack": 2, "probe_extra": 3, "probe_alt": 4, "hairpin": 5,
    "punch": 6, "success": 7, "nominate": 8, "accept": 9, "ready": 10, "handover_ack": 11,
}
ROLES = {"initiator": 1, "responder": 2, "server": 3}

# TLVs each type carries, in the ascending code order the encoder emits.
TLV_OBSERVED, TLV_EXTRA_PORT, TLV_COOKIE, TLV_SANDWICH, TLV_RX_COUNT = 1, 2, 3, 4, 5
TLV_PATH_SLOT, TLV_PATHS = 6, 7
CARRIES = {
    "probe": [TLV_SANDWICH],
    "probe_ack": [TLV_OBSERVED, TLV_EXTRA_PORT, TLV_COOKIE],
    "probe_extra": [TLV_OBSERVED],
    "probe_alt": [TLV_OBSERVED],
    "success": [TLV_OBSERVED, TLV_RX_COUNT],
    "nominate": [TLV_PATH_SLOT],
    "accept": [TLV_RX_COUNT, TLV_PATH_SLOT, TLV_PATHS],
    "ready": [TLV_PATHS],
    "handover_ack": [TLV_RX_COUNT],
}

TOKEN = bytes(range(0x00, 0x20))
ROUTE = bytes(range(0x20, 0x30))


def encode_header(h):
    flags = ROLES[h["role"]]
    for bit, name in ((2, "low_ttl"), (3, "retx"), (4, "fa"), (5, "fb"), (6, "fc")):
        if h[name]:
            flags |= 1 << bit
    return struct.pack(">BBBBHHIIII", TYPES[h["type"]], flags, h["round"], h["sock"], h["cand"],
                       h["aux"], h["seq"], h["ts"], h["echo_seq"], h["echo_ts"])


def encode_tlvs(typ, t):
    out = b""
    for code in CARRIES.get(typ, []):
        if code == TLV_OBSERVED:
            host, port = t["observed"].rsplit(":", 1)
            ip = ipaddress.ip_address(host.strip("[]"))
            raw = ip.packed if ip.version == 6 else b"\x00" * 10 + b"\xff\xff" + ip.packed
            out += bytes([code, 18]) + raw + struct.pack(">H", int(port))
        elif code == TLV_EXTRA_PORT:
            out += bytes([code, 2]) + struct.pack(">H", t["extra_port"])
        elif code == TLV_COOKIE:
            out += bytes([code, 4]) + struct.pack(">I", t["cookie"])
        elif code == TLV_SANDWICH and t["sandwich"] is not None:
            out += bytes([code, 2, t["sandwich"]["round"], t["sandwich"]["phase"]])
        elif code == TLV_RX_COUNT and t["rx_count"] is not None:
            out += bytes([code, 4]) + struct.pack(">I", t["rx_count"])
        elif code == TLV_PATH_SLOT and t["slot"] is not None:
            out += bytes([code, 1, t["slot"]])
        elif code == TLV_PATHS and t["paths"] is not None:
            out += bytes([code, 1, t["paths"]])
    return out


def seal(v):
    plain = encode_header(v["header"]) + encode_tlvs(v["header"]["type"], v["tlvs"])
    assert len(plain) <= v["plain_len"] <= 1024, v["name"]
    plain += bytes(v["plain_len"] - len(plain))  # zero padding; its first byte terminates the TLVs
    key = hkdf(TOKEN, ROUTE, LABEL_AEAD, 32)
    nonce = bytes.fromhex(v["nonce"])
    b0 = bytes([v["b0"]])
    outer = b0 + nonce
    if v["header"]["type"] == "probe":
        mask = hashlib.sha256(LABEL_MASK + nonce).digest()[:16]
        outer += bytes(a ^ b for a, b in zip(ROUTE, mask))
    v["plaintext"] = plain.hex()
    v["wire"] = (outer + gcm_seal(key, nonce, plain, b0 + ROUTE)).hex()


def header(typ, role, **kw):
    h = {"type": typ, "role": role, "low_ttl": False, "retx": False, "fa": False, "fb": False,
         "fc": False, "round": 0, "sock": 0, "cand": 0xFFFF, "aux": 0, "seq": 1, "ts": 0,
         "echo_seq": 0, "echo_ts": 0}
    h.update(kw)
    return h


def tlvs(observed="", extra_port=0, cookie=0, sandwich=None, rx_count=None, slot=None, paths=None):
    return {"observed": observed, "extra_port": extra_port, "cookie": cookie,
            "sandwich": sandwich, "rx_count": rx_count, "slot": slot, "paths": paths}


CASES = [
    ("probe", "probe/plain", 96, header("probe", "initiator", aux=2, seq=1, ts=10), tlvs()),
    ("probe", "probe/want-extra-sandwich", 176,
     header("probe", "responder", fa=True, low_ttl=True, round=3, sock=0x81, aux=5, seq=77, ts=123456),
     tlvs(sandwich={"round": 3, "phase": 1})),
    ("probe", "probe/want-alt", 224, header("probe", "initiator", fb=True, retx=True, sock=4, aux=9,
                                             seq=0x01020304, ts=0xFFFFFFFF), tlvs()),
    ("probe", "probe/min-wire-69", 24, header("probe", "initiator", aux=1, seq=2, ts=11), tlvs()),
    ("probe", "probe/max-wire-1069", 1024,
     header("probe", "responder", aux=0x00FF, seq=3, ts=12), tlvs(sandwich={"round": 0, "phase": 0})),
    ("probe_ack", "probe_ack/v4-min", 54,
     header("probe_ack", "server", fa=True, fc=True, sock=0x81, aux=5, seq=9, ts=0xDEADBEEF,
            echo_seq=77, echo_ts=123456),
     tlvs(observed="203.0.113.7:40000", extra_port=51000, cookie=0xA1B2C3D4)),
    ("probe_ack", "probe_ack/v6", 200,
     header("probe_ack", "server", fb=True, sock=0x80, aux=2, seq=10, ts=1, echo_seq=1, echo_ts=10),
     tlvs(observed="[2001:db8::1]:65535")),
    ("probe_extra", "probe_extra/v4-min", 44,
     header("probe_extra", "server", sock=1, aux=5, seq=11, ts=2, echo_seq=77, echo_ts=123456),
     tlvs(observed="198.51.100.20:1")),
    ("probe_alt", "probe_alt/v6", 300,
     header("probe_alt", "server", sock=0x82, aux=6, seq=12, ts=3, echo_seq=78, echo_ts=123457),
     tlvs(observed="[2001:db8:1::42]:3478")),
    ("hairpin", "hairpin", 48, header("hairpin", "initiator", sock=1, seq=3, ts=55), tlvs()),
    ("punch", "punch/low-ttl", 150,
     header("punch", "responder", low_ttl=True, round=2, sock=0x85, cand=(3 << 12) | 17, seq=1000,
            ts=2000), tlvs()),
    ("punch", "punch/min-wire-53", 24,
     header("punch", "initiator", round=1, cand=0, seq=1001, ts=2001), tlvs()),
    ("success", "success/rx", 100,
     header("success", "initiator", round=2, sock=2, cand=(3 << 12) | 17, seq=40, ts=2010,
            echo_seq=1000, echo_ts=2000),
     tlvs(observed="192.0.2.1:62000", rx_count=12)),
    ("success", "success/no-rx-min", 44,
     header("success", "responder", round=2, cand=5, seq=41, ts=2011, echo_seq=39, echo_ts=2009),
     tlvs(observed="[2001:db8::7]:443")),
    ("nominate", "nominate/min", 24,
     header("nominate", "initiator", round=2, sock=2, cand=(3 << 12) | 17, aux=1, seq=42, ts=2100),
     tlvs()),
    ("accept", "accept", 160,
     header("accept", "responder", round=2, sock=0x85, cand=(3 << 12) | 17, aux=1, seq=1002,
            ts=2150, echo_seq=42, echo_ts=2100), tlvs(rx_count=40)),
    ("ready", "ready/max-wire-1053", 1024,
     header("ready", "initiator", retx=True, round=2, sock=2, cand=(3 << 12) | 17, aux=1, seq=43,
            ts=2200, echo_seq=1002, echo_ts=2150), tlvs()),
    ("handover_ack", "handover_ack/min", 30,
     header("handover_ack", "responder", round=2, sock=0x85, cand=(3 << 12) | 17, aux=1, seq=1003,
            ts=2210, echo_seq=43, echo_ts=2200), tlvs(rx_count=99)),
    # Extra paths: an extra path's nomination and
    # its accept carry PATH_SLOT; the primary's accept carries the room for
    # extra paths and ready the committed slots in PATHS.
    ("nominate", "nominate/extra-slot", 40,
     header("nominate", "initiator", round=2, sock=0x81, aux=3, seq=44, ts=2120), tlvs(slot=2)),
    ("accept", "accept/extra-slot", 60,
     header("accept", "responder", round=2, sock=0x86, aux=3, seq=1004, ts=2160, echo_seq=44,
            echo_ts=2120), tlvs(rx_count=41, slot=2)),
    ("accept", "accept/room", 64,
     header("accept", "responder", round=2, sock=0x85, aux=3, seq=1005, ts=2161), tlvs(rx_count=42, paths=7)),
    ("ready", "ready/paths", 48,
     header("ready", "initiator", round=2, sock=2, aux=3, seq=45, ts=2220), tlvs(paths=0b10000110)),
]


def kdf_vector():
    nonce = bytes(range(0x30, 0x3C))
    role, rnd, seed = 1, 1, 0x01020304
    pacer_info = LABEL_PACER + bytes([role])
    spray_info = LABEL_SPRAY + bytes([role, rnd]) + struct.pack(">I", seed)
    return {
        "token": TOKEN.hex(),
        "route": ROUTE.hex(),
        "nonce": nonce.hex(),
        "role": "initiator",
        "round": rnd,
        "seed": seed,
        "key_info": LABEL_AEAD.hex(),
        "key": hkdf(TOKEN, ROUTE, LABEL_AEAD, 32).hex(),
        "mask_input": (LABEL_MASK + nonce).hex(),
        "mask": hashlib.sha256(LABEL_MASK + nonce).digest()[:16].hex(),
        "pacer_info": pacer_info.hex(),
        "pacer": hkdf(TOKEN, ROUTE, pacer_info, 32).hex(),
        "spray_info": spray_info.hex(),
        "spray": hkdf(TOKEN, ROUTE, spray_info, 32)[:8].hex(),
    }


def main():
    self_test()
    out = sys.argv[1] if len(sys.argv) > 1 else os.path.dirname(os.path.abspath(__file__))
    with open(os.path.join(out, "kdf.json"), "w") as f:
        json.dump(kdf_vector(), f, indent=2)
        f.write("\n")
    files = {}
    for i, (typ, name, plain_len, h, t) in enumerate(CASES):
        v = {
            "name": name,
            "token": TOKEN.hex(),
            "route": ROUTE.hex(),
            "b0": 0x04 + i % 12,
            "nonce": bytes((0x30 + 16 * i + j) & 0xFF for j in range(12)).hex(),
            "plain_len": plain_len,
            "header": h,
            "tlvs": t,
        }
        seal(v)
        files.setdefault(typ, []).append(v)
    assert set(files) == set(TYPES), "every packet type needs a vector"
    os.makedirs(os.path.join(out, "wire"), exist_ok=True)
    for typ, vs in files.items():
        with open(os.path.join(out, "wire", typ + ".json"), "w") as f:
            json.dump(vs, f, indent=2)
            f.write("\n")


if __name__ == "__main__":
    main()
