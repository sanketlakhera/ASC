#!/usr/bin/env python3
"""INSN_VERIFY differential: Python's two compiled patterns vs `asc verify-insns`.

Generates seeded instruction streams (insn_streams.stream), asks Python for
both forms of INSN_VERIFY (atomic group, and the 3.10 fallback without it),
pipes the same streams through the Rust walk, and reports every stream where
any two of the three disagree. The M2 exit runs 10^6 streams; CI runs the
committed vectors/insn_verify.json through `cargo test`.

Usage: verify_differential.py --bin ../target/release/asc [--streams 1000000] [--seed 1]
"""
import argparse
import random
import subprocess
import sys

import insn_streams


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--bin", required=True)
    ap.add_argument("--streams", type=int, default=1000000)
    ap.add_argument("--seed", type=int, default=1)
    ap.add_argument("--chunk", type=int, default=100000)
    args = ap.parse_args()

    rng = random.Random(args.seed)
    patterns = insn_streams.compile_patterns()
    done = variant_split = rust_diff = accepted = 0
    examples = []
    while done < args.streams:
        n = min(args.chunk, args.streams - done)
        cases = [insn_streams.stream(rng) for _ in range(n)]
        # an empty stream is sent as "-"
        payload = "".join(f"{buf.hex() or '-'} {s} {e}\n" for buf, s, e in cases)
        res = subprocess.run([args.bin, "verify-insns"], input=payload, capture_output=True, text=True)
        if res.returncode != 0:
            print(f"asc verify-insns failed: {res.stderr.strip()}", file=sys.stderr)
            return 2
        rust = res.stdout.split()
        if len(rust) != n:
            print(f"expected {n} answers, got {len(rust)}", file=sys.stderr)
            return 2
        for (buf, s, e), r in zip(cases, rust):
            atomic, plain = insn_streams.verdicts(patterns, buf, s, e)
            accepted += atomic
            if atomic != plain:
                variant_split += 1
            if (r == "1") != atomic:
                rust_diff += 1
                if len(examples) < 10:
                    examples.append((buf.hex(), s, e, atomic, plain, r))
        done += n
        print(f"... {done}/{args.streams} streams", file=sys.stderr)
    print(f"{done} streams, {accepted} accepted by Python; "
          f"atomic vs plain differ on {variant_split}; Rust differs on {rust_diff}")
    for ex in examples:
        print("  hex=%s start=%d end=%d atomic=%s plain=%s rust=%s" % ex)
    return 1 if (variant_split or rust_diff) else 0


if __name__ == "__main__":
    sys.exit(main())
