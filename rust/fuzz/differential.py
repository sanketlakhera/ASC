#!/usr/bin/env python3
"""Differential check: Python primitive dump vs `asc dump-primitives` on fuzz inputs.

Each input is wrapped as `classes.dex` in a stored APK, dumped by both sides, and the
parsed JSON trees compared. The fuzzers look for panics; this looks for inputs the
Rust side accepts or rejects differently from the oracle.

Usage: differential.py --bin ../target/release/asc [--limit N] DIR_OR_FILE...
"""

import argparse
import json
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "rust" / "conformance"))
from dump_primitives import dump_apk_primitives  # noqa: E402


def first_diff(a, b, path="$"):
    if type(a) is not type(b):
        return path, a, b
    if isinstance(a, dict):
        for k in sorted(set(a) | set(b)):
            if k not in a or k not in b:
                return f"{path}.{k}", a.get(k, "<missing>"), b.get(k, "<missing>")
            d = first_diff(a[k], b[k], f"{path}.{k}")
            if d:
                return d
        return None
    if isinstance(a, list):
        for i, (x, y) in enumerate(zip(a, b)):
            d = first_diff(x, y, f"{path}[{i}]")
            if d:
                return d
        if len(a) != len(b):
            return f"{path}.length", len(a), len(b)
        return None
    return None if a == b else (path, a, b)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--bin", required=True)
    ap.add_argument("--limit", type=int, default=0)
    ap.add_argument("inputs", nargs="+")
    args = ap.parse_args()
    # DEX strings may hold lone surrogates; never let reporting crash the run.
    sys.stdout.reconfigure(errors="backslashreplace")
    sys.stderr.reconfigure(errors="backslashreplace")

    files = []
    for inp in map(Path, args.inputs):
        files.extend(sorted(p for p in inp.iterdir() if p.is_file()) if inp.is_dir() else [inp])
    if args.limit:
        files = files[: args.limit]

    diffs = 0
    with tempfile.TemporaryDirectory() as tmp:
        for n, f in enumerate(files, 1):
            # A fresh path per input: apk_handler caches the mmap by path.
            apk = Path(tmp) / f"input{n}.apk"
            with zipfile.ZipFile(apk, "w", zipfile.ZIP_STORED) as z:
                z.writestr("classes.dex", f.read_bytes())
            expected = json.loads(json.dumps(dump_apk_primitives(apk), sort_keys=True))
            res = subprocess.run([args.bin, "dump-primitives", str(apk)], capture_output=True, text=True)
            if res.returncode != 0:
                diffs += 1
                print(f"CRASH {f.name}: exit {res.returncode}: {res.stderr.strip()[:300]}")
                continue
            d = first_diff(expected, json.loads(res.stdout))
            if d:
                diffs += 1
                path, py, rs = d
                print(f"DIFF {f.name}: {path}\n  python: {str(py)[:200]}\n  rust:   {str(rs)[:200]}")
            apk.unlink()
            if n % 200 == 0:
                print(f"... {n}/{len(files)} checked, {diffs} differing", file=sys.stderr)

    print(f"{len(files)} inputs, {diffs} differing")
    sys.exit(1 if diffs else 0)


if __name__ == "__main__":
    main()
