#!/usr/bin/env python3
"""Vector generator for Droid ASC M1 conformance tests.

Generates:
  vectors/uleb128.json
  vectors/sleb128.json
  vectors/mutf8.json
  vectors/zip_names.json
"""
import itertools
import json
from pathlib import Path
import random
import struct
import sys

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from droidasc.asc_core.utils import leb128
from droidasc.asc_core.utils import mutf8

RNG = random.Random(1234)


def gen_uleb128_vectors() -> list[dict]:
    test_bytes = [0x00, 0x01, 0x7E, 0x7F, 0x80, 0x81, 0xFE, 0xFF]
    cases = []
    seen = set()

    def add_buf(b: bytes):
        if b in seen:
            return
        seen.add(b)
        res = {"input_hex": b.hex()}
        try:
            val, sz = leb128.read_uleb128_fast(b, 0)
            res["fast"] = {"value": val, "size": sz}
        except ValueError as e:
            res["fast"] = {"error": str(e)}

        try:
            sz_len = leb128.read_uleb128_len(b, 0)
            res["len"] = {"size": sz_len}
        except ValueError as e:
            res["len"] = {"error": str(e)}
        cases.append(res)

    # Empty buffer
    add_buf(b"")

    # 1 to 5 bytes exhaustive combination of boundary values
    for length in range(1, 4):
        for combo in itertools.product(test_bytes, repeat=length):
            add_buf(bytes(combo))

    # For 4 and 5 bytes, sample boundaries
    for length in (4, 5):
        for _ in range(500):
            add_buf(bytes(RNG.choice(test_bytes) for _ in range(length)))

    # 2000 random buffers of length 1 to 8
    for _ in range(2000):
        length = RNG.randint(1, 8)
        add_buf(bytes(RNG.randint(0, 255) for _ in range(length)))

    return cases


def gen_sleb128_vectors() -> list[dict]:
    test_bytes = [0x00, 0x01, 0x3F, 0x40, 0x7F, 0x80, 0xBF, 0xC0, 0xFF]
    cases = []
    seen = set()

    def add_buf(b: bytes):
        if b in seen:
            return
        seen.add(b)
        res = {"input_hex": b.hex()}
        try:
            val, sz = leb128.read_sleb128(b, 0)
            res["value_str"] = str(val)
            res["value_i64"] = val if -(2**63) <= val < 2**63 else None
            res["size"] = sz
        except ValueError as e:
            res["error"] = str(e)
        cases.append(res)

    add_buf(b"")
    for length in range(1, 4):
        for combo in itertools.product(test_bytes, repeat=length):
            add_buf(bytes(combo))

    for length in range(4, 11):
        for _ in range(300):
            add_buf(bytes(RNG.choice(test_bytes) for _ in range(length)))

    for _ in range(2000):
        length = RNG.randint(1, 10)
        add_buf(bytes(RNG.randint(0, 255) for _ in range(length)))

    return cases


def to_utf16_units(s: str) -> list[int]:
    raw_le = s.encode("utf-16-le", "surrogatepass")
    return list(struct.unpack(f"<{len(raw_le) >> 1}H", raw_le))


def gen_mutf8_vectors() -> dict:
    decode_cases = []
    encode_cases = []

    # Interesting byte patterns for decoding
    sample_texts = [
        "",
        "hello world",
        "tok\x00en",
        "\U0001F600",
        "\U00010000",
        "\U0010FFFF",
        "\ud800",
        "\udfff",
        "abc\ud800def",
        "éèêëàâôûîïç",
        "\u4e16\u754c",
        "\ufffd",
    ]

    for t in sample_texts:
        enc = mutf8.encode_mutf8(t)
        dec = mutf8.decode_mutf8(enc)
        decode_cases.append({
            "input_hex": enc.hex(),
            "units": to_utf16_units(dec),
        })
        encode_cases.append({
            "units": to_utf16_units(t),
            "encoded_hex": enc.hex(),
            "utf16_len": mutf8.utf16_len(t),
        })

    # Add raw byte patterns (C0 80, overlongs, truncated, invalid UTF-8)
    raw_patterns = [
        b"\xc0\x80",
        b"a\xc0\x80b",
        b"\xff\xfe",
        b"\x80",
        b"\xc0",
        b"\xe0\x80",
        b"\xed\xa0\x80",  # lone surrogate \ud800
        b"\xed\xbf\xbf",  # lone surrogate \udfff
        b"\xed\xa0\xbd\xed\xb8\x80",  # surrogate pair emoji
        b"\xf0\x90\x80\x80",  # 4-byte standard UTF-8 (not MUTF-8)
        b"\xc1\x80",
        b"\xe0\x80\x80",
        b"\xed\xa0\x80\xed\xa0\x80",
    ]
    for p in raw_patterns:
        dec = mutf8.decode_mutf8(p)
        decode_cases.append({
            "input_hex": p.hex(),
            "units": to_utf16_units(dec),
        })

    # Random byte buffers for decode (5,000 cases)
    while len(decode_cases) < 5000:
        length = RNG.randint(0, 32)
        # Mix ascii, utf-8 headers, and random bytes
        b = bytearray()
        for _ in range(length):
            r = RNG.random()
            if r < 0.4:
                b.append(RNG.randint(0x20, 0x7E))
            elif r < 0.6:
                b.extend(b"\xc0\x80")
            elif r < 0.8:
                b.extend(b"\xed\xa0\xbd\xed\xb8\x80")
            else:
                b.append(RNG.randint(0, 255))
        b = bytes(b)
        dec = mutf8.decode_mutf8(b)
        decode_cases.append({
            "input_hex": b.hex(),
            "units": to_utf16_units(dec),
        })

    # Random unit lists for encode (5,000 cases)
    while len(encode_cases) < 5000:
        length = RNG.randint(0, 32)
        units = []
        for _ in range(length):
            r = RNG.random()
            if r < 0.5:
                units.append(RNG.randint(0, 127))
            elif r < 0.8:
                units.append(RNG.randint(128, 0xD7FF))
            elif r < 0.9:
                units.append(RNG.randint(0xD800, 0xDFFF))  # surrogate
            else:
                units.append(RNG.randint(0xE000, 0xFFFF))
        s = "".join(chr(u) for u in units)
        enc = mutf8.encode_mutf8(s)
        encode_cases.append({
            "units": units,
            "encoded_hex": enc.hex(),
            "utf16_len": mutf8.utf16_len(s),
        })

    return {"decode": decode_cases, "encode": encode_cases}


def gen_zip_names_vectors() -> list[dict]:
    cases = []
    sample_bytes = [
        b"classes.dex",
        b"classes2.dex",
        b"classes\xff.dex",
        b"test\xc0\x80.dex",
        b"invalid\xfe\xffname.dex",
        b"\x80\x81\x82.dex",
        b"normal/path.dex",
        b"simple.txt",
    ]
    for b in sample_bytes:
        cases.append({
            "input_hex": b.hex(),
            "decoded_ignore": b.decode("utf-8", errors="ignore"),
        })

    for _ in range(1000):
        length = RNG.randint(1, 40)
        raw = bytes(RNG.randint(0, 255) for _ in range(length))
        cases.append({
            "input_hex": raw.hex(),
            "decoded_ignore": raw.decode("utf-8", errors="ignore"),
        })

    return cases


def main():
    out_dir = ROOT / "rust" / "conformance" / "vectors"
    out_dir.mkdir(parents=True, exist_ok=True)

    print("Generating vectors/uleb128.json...")
    uleb_cases = gen_uleb128_vectors()
    (out_dir / "uleb128.json").write_text(json.dumps(uleb_cases, indent=2), encoding="utf-8")

    print("Generating vectors/sleb128.json...")
    sleb_cases = gen_sleb128_vectors()
    (out_dir / "sleb128.json").write_text(json.dumps(sleb_cases, indent=2), encoding="utf-8")

    print("Generating vectors/mutf8.json...")
    mutf8_cases = gen_mutf8_vectors()
    (out_dir / "mutf8.json").write_text(json.dumps(mutf8_cases, indent=2), encoding="utf-8")

    print("Generating vectors/zip_names.json...")
    zip_cases = gen_zip_names_vectors()
    (out_dir / "zip_names.json").write_text(json.dumps(zip_cases, indent=2), encoding="utf-8")

    print("Vector generation complete!")


if __name__ == "__main__":
    main()
