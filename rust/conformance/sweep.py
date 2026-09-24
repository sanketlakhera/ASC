#!/usr/bin/env python3
"""Corrupt-input sweep over the Python oracle.

Truncates and mutates the dex_fixture DEXes, drives the findrefs and getclass
engine paths in-process, and classifies every outcome:

  ok        the call returned
  contract  a ValueError whose text matches a literal ValueError message in droidasc/
  LEAK      any other exception (struct.error, IndexError, ...)
  TIMEOUT   the call did not return within the watchdog

This is the M0 verification sweep (docs/M0_VERIFICATION.md, round 2) made
reproducible; the defaults are that run: Random(1234), 70 single-byte and
30 four-byte mutations per base, 3 s / 5 s watchdog, 2,700 cases.

Usage (from the repository root, in the oracle environment):
  uv run --python 3.12 --with "androguard==4.1.3" \\
      python rust/conformance/sweep.py mut --report sweep_mut.txt --save-dir hangs/
  ... sweep.py trunc   # every truncation length (16,488 cases, slow)

--root runs the sweep against another checkout (e.g. a worktree at oracle-m0).
--save-dir writes every TIMEOUT and LEAK input as <label>.dex for reuse as
fuzz seeds or corpus fixtures.
"""
import argparse
import copy
import os
import random
import re
import signal
import sys
import tempfile
import zipfile
from collections import Counter, defaultdict
from pathlib import Path

parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
parser.add_argument("mode", choices=["mut", "trunc"])
parser.add_argument("--root", default=str(Path(__file__).resolve().parents[2]), help="checkout whose droidasc/ is swept")
parser.add_argument("--report", help="also write the report to this file")
parser.add_argument("--save-dir", help="write TIMEOUT and LEAK inputs here")
parser.add_argument("--byte-mutations", type=int, default=70, help="single-byte mutations per base")
parser.add_argument("--u32-mutations", type=int, default=30, help="4-byte mutations per base")
parser.add_argument("--findrefs-timeout", type=int, default=3)
parser.add_argument("--getclass-timeout", type=int, default=5)
parser.add_argument("--no-getclass", action="store_true", help="findrefs only (no androguard needed)")
args = parser.parse_args()

ROOT = Path(args.root).resolve()
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))

from dex_fixture import make_dex, make_static_field_dex, make_dex041_container  # noqa: E402
from droidasc.asc_client.apk_handler import ApkHandler  # noqa: E402
from droidasc.asc_client.asc_handler import AscHandler  # noqa: E402
from droidasc.asc_client.dex_container import iter_logical_dex_buffers  # noqa: E402

# Contract messages: every literal ValueError text in droidasc/, {..} -> .*, digits -> \d+.
CONTRACT = []
for p in ROOT.glob("droidasc/**/*.py"):
    for m in re.finditer(r'ValueError\(f?"([^"]*)"', p.read_text()):
        pattern = re.escape(re.sub(r"\{[^}]*\}", "\0", m.group(1))).replace("\0", ".*")
        CONTRACT.append(re.compile("^" + re.sub(r"\d+", r"\\d+", pattern) + "$"))


def is_contract(exc):
    return type(exc) is ValueError and any(c.match(str(exc)) for c in CONTRACT)


QUERIES = [
    ("string", {"string": "token"}),
    ("type", {"type": "Lexample/Test;"}),
    ("method", {"method": {"class": ["Lexample/Test;", True], "method": "first"}}),
    ("method", {"method": {"class": None, "method": "first"}}),
    ("method", {"method": {"class": ["example", False], "method": None}}),
    ("field", {"field": {"class": ["Lexample/Statics;", True], "field": "SECOND"}}),
    ("field", {"field": {"class": None, "field": "SECOND"}}),
]
GETCLASS_TARGETS = ("Lexample/Test;", "Lexample/Statics;")


class Timeout(Exception):
    pass


def _alarm(signum, frame):
    raise Timeout("timeout")


signal.signal(signal.SIGALRM, _alarm)


def run_findrefs(buf, ft, q):
    for name, logical in iter_logical_dex_buffers("classes.dex", buf):
        AscHandler().findrefs(name, logical, ft, copy.deepcopy(q))


def run_getclass(buf, cls):
    with tempfile.NamedTemporaryFile(suffix=".apk", delete=False) as f:
        path = f.name
    try:
        with zipfile.ZipFile(path, "w") as zf:
            zf.writestr("classes.dex", buf)
        hit = ApkHandler(path, max_workers=1).get_class_dex(cls)
        if hit is None:
            raise ValueError(f"Class {cls} not found in APK.")
        AscHandler().getclass(hit[1], cls)
    finally:
        os.unlink(path)


results = defaultdict(Counter)  # path -> Counter[(kind, type, normalised message)]
examples = {}
saved = set()


def record(path, label, buf, exc, where):
    if exc is None:
        key = ("ok", "", "")
    elif isinstance(exc, Timeout):
        key = ("TIMEOUT", "Timeout", where)
    elif is_contract(exc):
        key = ("contract", "ValueError", re.sub(r"\d+", "N", str(exc))[:80])
    else:
        key = ("LEAK", type(exc).__name__, re.sub(r"\d+", "N", str(exc))[:100])
    results[path][key] += 1
    examples.setdefault((path, key), label)
    if args.save_dir and key[0] in ("TIMEOUT", "LEAK") and label not in saved:
        saved.add(label)
        out = Path(args.save_dir)
        out.mkdir(parents=True, exist_ok=True)
        (out / (re.sub(r"[^\w@.-]", "_", label) + ".dex")).write_bytes(buf)


def innermost_droidasc_frame(tb):
    """file:line of the deepest droidasc frame, to say where a timeout spun."""
    where = ""
    while tb is not None:
        f = tb.tb_frame.f_code.co_filename
        if "droidasc" in f:
            where = f"{Path(f).name}:{tb.tb_lineno} {tb.tb_frame.f_code.co_name}"
        tb = tb.tb_next
    return where


def attempt(fn, seconds):
    signal.alarm(seconds)
    try:
        fn()
        return None, ""
    except BaseException as e:  # noqa: BLE001 - classifying every outcome is the point
        return e, innermost_droidasc_frame(e.__traceback__) if isinstance(e, Timeout) else ""
    finally:
        signal.alarm(0)


def exercise(label, buf):
    for ft, q in QUERIES:
        exc, where = attempt(lambda: run_findrefs(buf, ft, q), args.findrefs_timeout)
        record(f"findrefs/{ft}", label, buf, exc, where)
    if not args.no_getclass:
        for cls in GETCLASS_TARGETS:
            exc, where = attempt(lambda: run_getclass(buf, cls), args.getclass_timeout)
            record("getclass", label, buf, exc, where)


bases = {
    "dex": make_dex(),
    "static": make_static_field_dex(),
    "dex041": make_dex041_container({}, {"padding": 64}),
}

inputs = 0
if args.mode == "trunc":
    for bname, base in bases.items():
        for n in range(len(base)):
            exercise(f"{bname} trunc {n}", base[:n])
            inputs += 1
else:
    # Same draw order as the M0 run, so labels and inputs are reproducible.
    rng = random.Random(1234)
    for bname, base in bases.items():
        for _ in range(args.byte_mutations):
            b = bytearray(base)
            pos = rng.randrange(len(b))
            b[pos] = rng.randrange(256)
            exercise(f"{bname} byte@{pos}", bytes(b))
            inputs += 1
        for _ in range(args.u32_mutations):
            b = bytearray(base)
            pos = rng.randrange(0, len(b) - 4)
            b[pos:pos + 4] = rng.choice([b"\xff\xff\xff\xff", b"\x00\x00\x00\x00", rng.randbytes(4)])
            exercise(f"{bname} u32@{pos}", bytes(b))
            inputs += 1

lines = [f"root: {ROOT}", f"inputs: {inputs}, cases: {sum(sum(c.values()) for c in results.values())}", ""]
totals = Counter()
for path in sorted(results):
    lines.append(f"== {path}")
    for key, n in sorted(results[path].items(), key=lambda kv: (kv[0][0] not in ("LEAK", "TIMEOUT"), -kv[1])):
        kind, t, msg = key
        totals[kind] += n
        lines.append(f"  {kind:8} {n:6}  {t:12} {msg!r:70}  e.g. {examples[(path, key)]}")
    lines.append("")
lines.append("totals: " + ", ".join(f"{k} {v}" for k, v in sorted(totals.items())))
report = "\n".join(lines) + "\n"
print(report)
if args.report:
    Path(args.report).write_text(report)
sys.exit(1 if totals["LEAK"] or totals["TIMEOUT"] else 0)
