#!/usr/bin/env python3
"""Write fuzz seed inputs under rust/fuzz/seeds/<target>/.

Seeds come from the conformance corpus (APKs, their DEX entries, the DEX 041
logical buffers) and the conformance vector files, plus deterministic
mutations of the corpus DEXes that target class_data counts and table sizes,
the inputs the M0 sweep found hanging the Python walker. Random(1234) keeps
the output stable, so re-running the script does not churn the committed seeds.
"""

import hashlib
import json
import random
import struct
import zipfile
import zlib
from pathlib import Path

HERE = Path(__file__).resolve().parent
CONF = HERE.parent / "conformance"
OUT = HERE / "seeds"
MAX_SEED = 1 << 20  # keep committed seeds small; bigger DEXes stay out of git


def put(target, data):
    if len(data) > MAX_SEED:
        return
    d = OUT / target
    d.mkdir(parents=True, exist_ok=True)
    (d / hashlib.sha1(data).hexdigest()).write_bytes(data)


def read_uleb(buf, pos):
    result = shift = 0
    while True:
        b = buf[pos]
        pos += 1
        result |= (b & 0x7F) << shift
        shift += 7
        if b < 0x80:
            return result, pos


def mutations(dex, rng):
    """Yield DEX buffers with corrupted counts and offsets."""
    if len(dex) < 0x70:
        return
    # Table sizes set huge, one at a time.
    for size_off in (0x38, 0x40, 0x48, 0x50, 0x58, 0x60):
        m = bytearray(dex)
        m[size_off:size_off + 4] = struct.pack("<I", rng.choice([0xFFFFFFFF, 0x7FFFFFFF, len(dex)]))
        yield bytes(m)
    # class_data: overwrite each of the four leading uleb counts with a 5-byte maximum.
    cd_size, cd_off = struct.unpack_from("<II", dex, 0x60)
    for i in range(min(cd_size, 4)):
        data_off = struct.unpack_from("<I", dex, cd_off + i * 32 + 24)[0] if cd_off + i * 32 + 28 <= len(dex) else 0
        if not data_off or data_off >= len(dex):
            continue
        pos = data_off
        for _ in range(4):
            start = pos
            _, pos = read_uleb(dex, pos)
            m = bytearray(dex)
            m[start:pos] = b"\xff\xff\xff\xff\x0f"
            yield bytes(m)
    # Random byte flips.
    for _ in range(8):
        m = bytearray(dex)
        for _ in range(rng.randint(1, 16)):
            m[rng.randrange(len(m))] = rng.randrange(256)
        yield bytes(m)


def main():
    rng = random.Random(1234)
    dexes = []
    for apk in sorted((CONF / "corpus").glob("*.apk")):
        data = apk.read_bytes()
        put("zip_cd", data)
        put("inflate", data)
        try:
            with zipfile.ZipFile(apk) as z:
                for name in z.namelist():
                    if name.endswith(".dex") and "/" not in name:
                        dexes.append(z.read(name))
        except (zipfile.BadZipFile, OSError, zlib.error):  # corrupt fixtures
            pass

    for dex in dexes:
        for target in ("dex_header", "container", "tinydex_walk"):
            put(target, dex)
        for m in mutations(dex, rng):
            put("tinydex_walk", m)

    vectors = CONF / "vectors"
    for case in json.loads((vectors / "mutf8.json").read_text())["decode"][:300]:
        put("mutf8", bytes.fromhex(case["input_hex"]))
    for name in ("uleb128.json", "sleb128.json"):
        for case in json.loads((vectors / name).read_text())[:200]:
            put("leb128", b"\x00" + bytes.fromhex(case["input_hex"]))

    for d in sorted(OUT.iterdir()):
        print(f"{d.name}: {len(list(d.iterdir()))} seeds")


if __name__ == "__main__":
    main()
