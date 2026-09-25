#!/usr/bin/env python3
"""Pattern differential: Python `re` (bytes) vs the Rust translation (M2 plan section 5).

Random patterns from a grammar of Python regex syntax are compiled by Python
and by `asc regex-probe`, and run over real string_data (the workload DEX's
region, or a slice of it). Per pattern:

  - Python raises    -> Rust must report the same message (re.error text,
                        OverflowError / ValueError text);
  - Python compiles  -> Rust matches, or refuses with "unsupported pattern
                        syntax" only when the pattern uses a construct the
                        grammar marks unsupported (lookaround, backreference,
                        conditional, atomic group, possessive repeat, L flag);
  - both match       -> the set of first-NUL-after-match-end positions must be
                        equal (that is all a string query depends on); match
                        spans are compared too and reported separately, since
                        the engines iterate empty matches after an empty match
                        differently.

Usage: regex_differential.py --bin ../target/release/asc [--patterns 20000] [--seed 1] [--haystack-kb 64]
"""
import argparse
import hashlib
import json
import random
import re
import signal
import subprocess
import sys
import tempfile
import warnings
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from droidasc.asc_core.findrefs.locator.string_locator import StringLocator  # noqa: E402
from droidasc.asc_core.utils.mutf8 import encode_mutf8  # noqa: E402
from droidasc.asc_core.utils.tinydex import DEX  # noqa: E402

warnings.simplefilter("ignore")

LETTERS = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_"
PUNCT = "/;$<>-!@#%&~`'\",:=_ "
COMMON = ["create", "token", "View", "on", "get", "set", "Landroid", "Ljava/lang", "init", "a", "e", "tion", "Layout"]
NON_ASCII = ["é", "ÿ", "Ā", "中", "\U0001F600", "\x00"]


class Gen:
    def __init__(self, rng):
        self.rng = rng
        self.unsupported = False
        self.groups = 0
        self.names = []

    def pick(self, *weighted):
        total = sum(w for w, _ in weighted)
        r = self.rng.random() * total
        for w, f in weighted:
            r -= w
            if r <= 0:
                return f()
        return weighted[-1][1]()

    def literal(self):
        r = self.rng
        return self.pick(
            (6, lambda: r.choice(COMMON)),
            (4, lambda: r.choice(LETTERS)),
            (1, lambda: r.choice(NON_ASCII)),
            (1, lambda: "\\" + r.choice(".^$*+?{}[]()|\\/-<>#&~ ")),
            (1, lambda: r.choice(PUNCT)),
            (1, lambda: r.choice(["\\x41", "\\x2f", "\\x00", "\\0", "\\012", "\\n", "\\t", "\\a", "\\v", "\\f"])),
            (1, lambda: r.choice(["{", "}", "]", "{}", "a{", "{,", "x{1", "{1,", "{a}"])),
        )

    def cls(self):
        r = self.rng
        items = []
        for _ in range(r.randrange(1, 4)):
            items.append(self.pick(
                (4, lambda: r.choice(LETTERS)),
                (2, lambda: r.choice(["a-z", "A-Z", "0-9", "a-f", "\\x20-\\x2f", "!-/", "_-z"])),
                (2, lambda: r.choice(["\\d", "\\w", "\\s", "\\W", "\\D", "\\S"])),
                (1, lambda: r.choice(["\\b", "\\]", "\\\\", "\\-", "\\n", "\\x00", "\\0", "\\177"])),
                (1, lambda: r.choice(["-", "&&", "--", "~~", "[", "^", ".", "$", "|"])),
                (1, lambda: r.choice(NON_ASCII)),
            ))
        body = "".join(items)
        head = r.choice(["[", "[", "[^", "[]", "[^]"])
        return head + body + "]"

    def atom(self, depth):
        r = self.rng
        opts = [
            (8, self.literal),
            (2, lambda: "."),
            (3, self.cls),
            (1, lambda: r.choice(["\\d", "\\w", "\\s", "\\D", "\\W", "\\S"])),
            (1, lambda: r.choice(["^", "$", "\\A", "\\Z", "\\b", "\\B"])),
        ]
        if depth < 3:
            opts += [
                (2, lambda: "(" + self.alt(depth + 1) + ")"),
                (2, lambda: "(?:" + self.alt(depth + 1) + ")"),
                (1, lambda: "(?" + r.choice(["i", "s", "m", "x", "i-s", "-i", "a", "im"]) + ":" + self.alt(depth + 1) + ")"),
                (1, self.named),
                (1, self.unsupported_construct(depth)),
            ]
        return self.pick(*opts)

    def named(self):
        name = self.rng.choice(["n", "g1", "_x", "name", "1bad", "a-b"])
        self.names.append(name)
        return f"(?P<{name}>" + self.alt(9) + ")"

    def unsupported_construct(self, depth):
        def make():
            self.unsupported = True
            r = self.rng
            return r.choice([
                lambda: "(?=" + self.alt(depth + 1) + ")",
                lambda: "(?!" + self.alt(depth + 1) + ")",
                lambda: "(?<=" + r.choice(["a", "to", "L"]) + ")",
                lambda: "(?<!" + r.choice(["a", "to"]) + ")",
                lambda: "(?>" + self.alt(depth + 1) + ")",
                lambda: "(a)\\1",
                lambda: "(?P<z>a)(?P=z)",
                lambda: "(a)?(?(1)b|c)",
            ])()
        return make

    def repeat(self):
        r = self.rng
        q = r.choice(["*", "+", "?", "{2}", "{1,3}", "{,2}", "{2,}", "{0}", "{,}", "{3,1}", "{1,1}"])
        suffix = self.pick((8, lambda: ""), (3, lambda: "?"), (1, lambda: "+"))
        if suffix == "+":
            self.unsupported = True
        return q + suffix

    def seq(self, depth):
        out = ""
        for _ in range(self.rng.randrange(0, 4)):
            out += self.atom(depth)
            if self.rng.random() < 0.3:
                out += self.repeat()
        return out

    def alt(self, depth):
        parts = [self.seq(depth) for _ in range(self.rng.randrange(1, 3))]
        return "|".join(parts)

    def pattern(self):
        r = self.rng
        prefix = r.choice(["", "", "", "(?i)", "(?s)", "(?m)", "(?x)", "(?L)", "(?u)", "(?t)", "(?aL)"])
        if "L" in prefix or prefix == "(?t)":
            self.unsupported = True
        body = self.alt(0)
        if r.random() < 0.05:
            body += r.choice(["(", ")", "\\", "[", "(?", "(?P", "(?<", "(?#c", "a(?i)b", "\\8", "\\z", "\\u0041"])
        if r.random() < 0.05:
            body += r.choice(["(?#comment)", " #c\n x", "\n"])
        return prefix + body


def python_side(pattern_bytes, hay, timeout):
    try:
        compiled = re.compile(pattern_bytes)
    except Exception as e:  # re.error, OverflowError, ValueError, RecursionError
        return {"error": str(e)}

    def alarm(*_):
        raise TimeoutError

    signal.signal(signal.SIGALRM, alarm)
    signal.setitimer(signal.ITIMER_REAL, timeout)
    try:
        spans = []
        nuls = set()
        for m in compiled.finditer(hay):
            spans.append([m.start(), m.end()])
            n = hay.find(b"\x00", m.end())
            if n >= 0:
                nuls.add(n)
    except TimeoutError:
        return {"timeout": True}
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
    return {
        "spans": len(spans),
        "spans_sha256": hashlib.sha256(json.dumps(spans, separators=(",", ":")).encode()).hexdigest(),
        "nuls": len(nuls),
        "nuls_sha256": hashlib.sha256(json.dumps(sorted(nuls), separators=(",", ":")).encode()).hexdigest(),
    }


def workload_region():
    with zipfile.ZipFile(ROOT / "tests" / "fixtures" / "reference-workload.zip") as zf:
        raw = zf.read("classes.dex")
    loc = StringLocator(DEX.parse(memoryview(raw), "classes.dex"))
    loc._build_map()
    return raw[loc.strdata_start:loc.strdata_end]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--bin", required=True)
    ap.add_argument("--patterns", type=int, default=20000)
    ap.add_argument("--seed", type=int, default=1)
    ap.add_argument("--haystack-kb", type=int, default=64, help="0 for the whole region")
    ap.add_argument("--timeout", type=float, default=2.0)
    args = ap.parse_args()
    sys.stdout.reconfigure(errors="backslashreplace")

    region = workload_region()
    hay = region if args.haystack_kb == 0 else region[:args.haystack_kb * 1024]
    rng = random.Random(args.seed)
    cases = []
    for _ in range(args.patterns):
        g = Gen(rng)
        text = g.pattern()
        cases.append((text, encode_mutf8(text), g.unsupported))

    with tempfile.NamedTemporaryFile(suffix=".bin") as f:
        f.write(hay)
        f.flush()
        payload = "".join(p.hex() + "\n" for _, p, _ in cases)
        res = subprocess.run([args.bin, "regex-probe", f.name], input=payload, capture_output=True, text=True)
    if res.returncode:
        print(f"regex-probe failed: {res.stderr[:500]}")
        return 2
    rust = [json.loads(line) for line in res.stdout.splitlines()]
    assert len(rust) == len(cases), (len(rust), len(cases))

    counts = {"python_error": 0, "matched": 0, "unsupported": 0, "refused_empty_preferring": 0, "timeout": 0}
    problems = {"error_text": [], "error_kind": [], "wrong_unsupported": [], "nul_set": [], "spans_only": []}
    for (text, _, uses_unsupported), r in zip(cases, rust):
        py = python_side(encode_mutf8(text), hay, args.timeout)
        if "timeout" in py:
            counts["timeout"] += 1
            continue
        if "error" in py:
            counts["python_error"] += 1
            if "error" not in r:
                problems["error_kind"].append((text, py, r))
            elif r["error"] != py["error"]:
                problems["error_text"].append((text, py, r))
            continue
        if "unsupported" in r:
            # Refusing a pattern that can match empty and prefers an empty
            # option is by design (pattern.rs): CPython's finditer retries a
            # non-empty match where regex moves on. Sound as long as nul_set
            # stays 0 for everything accepted.
            if r["unsupported"].startswith("a pattern that can match empty"):
                counts["refused_empty_preferring"] += 1
                continue
            counts["unsupported"] += 1
            if not uses_unsupported:
                problems["wrong_unsupported"].append((text, py, r))
            continue
        if "error" in r:
            problems["error_kind"].append((text, py, r))
            continue
        counts["matched"] += 1
        if (py["nuls"], py["nuls_sha256"]) != (r["nuls"], r["nuls_sha256"]):
            problems["nul_set"].append((text, py, r))
        elif (py["spans"], py["spans_sha256"]) != (r["spans"], r["spans_sha256"]):
            problems["spans_only"].append((text, py, r))

    print(f"{len(cases)} patterns over {len(hay)} bytes: " + ", ".join(f"{k} {v}" for k, v in counts.items()))
    for kind, items in problems.items():
        print(f"  {kind}: {len(items)}")
        for text, py, r in items[:8]:
            print(f"    {text!r}\n      python: {py}\n      rust:   {r}")
    blocking = sum(len(problems[k]) for k in ("error_text", "error_kind", "wrong_unsupported", "nul_set"))
    return 1 if blocking else 0


if __name__ == "__main__":
    sys.exit(main())
