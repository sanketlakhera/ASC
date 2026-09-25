#!/usr/bin/env python3
"""Vector generator for Droid ASC M1 conformance tests.

Generates:
  vectors/uleb128.json
  vectors/sleb128.json
  vectors/mutf8.json
  vectors/zip_names.json
  vectors/insn_verify.json   (M2: INSN_VERIFY on 20,000 instruction streams)
  vectors/patterns.json      (M2: Python re outcome for findrefs patterns)
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


def gen_insn_verify_vectors(count: int = 20000) -> list[dict]:
    """Python's INSN_VERIFY verdict, both compiled forms, per stream. Its own
    RNG, so the other vector files do not move when this one changes."""
    sys.path.insert(0, str(ROOT / "rust" / "conformance"))
    import insn_streams

    rng = random.Random(4242)
    patterns = insn_streams.compile_patterns()
    cases = []
    for _ in range(count):
        buf, start, end = insn_streams.stream(rng)
        atomic, plain = insn_streams.verdicts(patterns, buf, start, end)
        cases.append({"hex": buf.hex(), "start": start, "end": end, "atomic": atomic, "plain": plain})
    return cases


# Hand-picked patterns for vectors/patterns.json, on top of the random ones:
# each probes a place where Python re and regex::bytes read syntax differently.
PATTERN_PROBES = [
    "token", "tok.n", "^tok", "(?i)TOKEN", "[a-c]reate", "token.", "a{", "a{,3}", "x{}", "{1", "e{1,}",
    "a{2,1}", "\\<", "[a&&b]", "[a--b]", "[a~~b]", "[[a]", "[]a]", "[^]a]", "(?<name>a)", "(?P<name>a)",
    "(?P<1a>x)", "a(?i)b", "(?i)(?s)x", "a|(?i)b", "\\x{41}", "\\x4", "\\x41", "\\u0041", "\\z", "\\Z",
    "\\A", "\\b", "[\\b]", "\\0", "\\012", "\\1", "(a)\\1", "\\8", "[\\8]", "\\777", "(?x) t o k", "(?x)[ ]",
    "(?x)a#c\nb", "(?#c)tok", "tok(?#c", "^*", "a**", "a*?", "a++", "a{2}+", "(?>a)", "(?=t)", "(?<=t)oken",
    "(?(1)a)", "(a)?(?(1)b|c)", "(?L)a", "(?u)a", "(?aL)a", "(?t)a", "(?t)a*", "(?-i:a)", "(?i-i:a)", "(?a-a:x)",
    "(", ")", "(?", "(?P", "[", "a\\", "|token", "token|", "x*|t", "t|x*", "(?:)", "()", "\u00e9", "[\u00e9]",
    "\U0001F600", "\x00", ".", "$", "\\$", "tok\n", "(?m)^L", "(?m)n$", "\\d+", "\\w+", "\\s", "[^\\W\\d]",
]


def gen_pattern_vectors(count: int = 3000) -> dict:
    """Python's outcome for each pattern over a fixed haystack: its re.error
    (or other exception) text, or the first-NUL-after-match-end positions.
    The haystack is make_dex()'s string_data plus some real-looking strings.
    Random patterns can backtrack for hours (`.*.*.*x`); one that takes more
    than a second in Python is left out."""
    import re as _re
    import signal as _signal
    import warnings as _warnings

    def _timeout(*_):
        raise TimeoutError

    _signal.signal(_signal.SIGALRM, _timeout)
    sys.path.insert(0, str(ROOT / "tests"))
    sys.path.insert(0, str(ROOT / "rust" / "conformance"))
    from regex_differential import Gen
    from droidasc.asc_core.utils.mutf8 import encode_mutf8

    words = [b"Lexample/Test;", b"Ljava/lang/Object;", b"V", b"first", b"second", b"token", b"create",
             b"onCreate", b"View", b"setView", b"Landroid/view/View;", b"a{b}", b"x{1,2}", b"<init>", b"-x",
             b"tok\xc0\x80en", b"caf\xc3\xa9", b"\xed\xa0\xbd\xed\xb8\x80", b"line\nbreak", b"a&&b", b"[x]"]
    hay = b"".join(bytes([len(w)]) + w + b"\0" for w in words)
    rng = random.Random(777)
    patterns = list(PATTERN_PROBES)
    while len(patterns) < count:
        patterns.append(Gen(rng).pattern())
    cases = []
    _warnings.simplefilter("ignore")
    for text in patterns:
        raw = encode_mutf8(text)
        try:
            compiled = _re.compile(raw)
        except Exception as e:
            cases.append({"pattern": to_utf16_units(text), "error": str(e)})
            continue
        nuls = set()
        _signal.setitimer(_signal.ITIMER_REAL, 1.0)
        try:
            for m in compiled.finditer(hay):
                n = hay.find(b"\0", m.end())
                if n >= 0:
                    nuls.add(n)
        except TimeoutError:
            continue
        finally:
            _signal.setitimer(_signal.ITIMER_REAL, 0)
        cases.append({"pattern": to_utf16_units(text), "nuls": sorted(nuls)})
    return {"haystack_hex": hay.hex(), "cases": cases}


def main():
    out_dir = ROOT / "rust" / "conformance" / "vectors"
    out_dir.mkdir(parents=True, exist_ok=True)

    print("Generating vectors/uleb128.json...", flush=True)
    uleb_cases = gen_uleb128_vectors()
    (out_dir / "uleb128.json").write_text(json.dumps(uleb_cases, indent=2), encoding="utf-8")

    print("Generating vectors/sleb128.json...", flush=True)
    sleb_cases = gen_sleb128_vectors()
    (out_dir / "sleb128.json").write_text(json.dumps(sleb_cases, indent=2), encoding="utf-8")

    print("Generating vectors/mutf8.json...", flush=True)
    mutf8_cases = gen_mutf8_vectors()
    (out_dir / "mutf8.json").write_text(json.dumps(mutf8_cases, indent=2), encoding="utf-8")

    print("Generating vectors/zip_names.json...", flush=True)
    zip_cases = gen_zip_names_vectors()
    (out_dir / "zip_names.json").write_text(json.dumps(zip_cases, indent=2), encoding="utf-8")

    print("Generating vectors/insn_verify.json...", flush=True)
    insn_cases = gen_insn_verify_vectors()
    (out_dir / "insn_verify.json").write_text(json.dumps(insn_cases, separators=(",", ":")), encoding="utf-8")

    print("Generating vectors/patterns.json...", flush=True)
    pattern_cases = gen_pattern_vectors()
    (out_dir / "patterns.json").write_text(json.dumps(pattern_cases, separators=(",", ":")), encoding="utf-8")

    print("Vector generation complete!")


if __name__ == "__main__":
    main()
