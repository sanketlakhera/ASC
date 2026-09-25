"""Instruction streams for the INSN_VERIFY conformance checks (M2 plan 4.5).

Python verifies a findrefs hit with `InsnLocator.INSN_VERIFY.fullmatch(buf,
start, end)`. The Rust port walks instructions instead; these streams, and
Python's answer for both compiled forms of the pattern (with the atomic group,
Python >= 3.11, and without it, the 3.10 fallback), are the evidence that the
walk and both regexes accept exactly the same ranges.

Streams are mostly real instruction sequences (so walks run long), with
undefined opcodes, truncated tails, starts and ends inside instructions,
start > end, and ends past the buffer mixed in.
"""
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from droidasc.asc_core.models import dvm_opcode  # noqa: E402


def compile_patterns():
    """(atomic, plain): INSN_VERIFY as InsnLocator builds it, in both forms."""
    groups = {1: [], 2: [], 3: [], 4: [], 5: []}
    for opcode, info in dvm_opcode.opcodes.items():
        groups[info.oplen].append(opcode)
    body = b"|".join(
        b"[" + re.escape(bytes(groups[n])) + b"]" + b"." * (n * 2 - 1) for n in groups
    )
    atomic = re.compile(b"(?>(?:" + body + b")*)", re.DOTALL)
    plain = re.compile(b"(?:" + body + b")*", re.DOTALL)
    return atomic, plain


DEFINED = sorted(dvm_opcode.opcodes)
UNDEFINED = [op for op in range(256) if op not in dvm_opcode.opcodes]


def stream(rng):
    """One (buf, start, end) case."""
    buf = bytearray()
    bounds = [0]
    for _ in range(rng.randrange(0, 10)):
        if UNDEFINED and rng.random() < 0.08:
            op = rng.choice(UNDEFINED)
            size = rng.randrange(1, 6) * 2
        else:
            op = rng.choice(DEFINED)
            size = dvm_opcode.opcodes[op].oplen * 2
        buf.append(op)
        buf += rng.randbytes(size - 1)
        bounds.append(len(buf))
    if rng.random() < 0.2:
        buf += rng.randbytes(rng.randrange(1, 4))
    n = len(buf)

    def point():
        r = rng.random()
        if r < 0.55:
            return rng.choice(bounds)
        if r < 0.9:
            return rng.randrange(0, n + 1)
        return n + rng.randrange(1, 6)

    start, end = point(), point()
    if rng.random() < 0.6 and start > end:
        start, end = end, start
    return bytes(buf), start, end


def verdicts(patterns, buf, start, end):
    atomic, plain = patterns
    return (atomic.fullmatch(buf, start, end) is not None,
            plain.fullmatch(buf, start, end) is not None)
