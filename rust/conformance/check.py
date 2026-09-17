#!/usr/bin/env python3
"""Conformance test runner: Check candidate Rust binary against golden oracle files.

Usage:
  python rust/conformance/check.py --bin path/to/asc [--golden-dir golden] [--corpus-dir corpus]
"""
import argparse
import difflib
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[2]

DEBUG_REGEX = re.compile(r"^\[DEBUG\].*$\n?", re.MULTILINE)
SEP_REGEX = re.compile(r"^-{40,}.*$\n?", re.MULTILINE)


def clean_cli_output(text: str, is_debug: bool = False) -> str:
    if not is_debug:
        return text
    text = DEBUG_REGEX.sub("", text)
    text = SEP_REGEX.sub("", text)
    return text


def diff_text(expected: str, actual: str, label: str = "") -> str:
    exp_lines = expected.splitlines(keepends=True)
    act_lines = actual.splitlines(keepends=True)
    diff = list(difflib.unified_diff(exp_lines, act_lines, fromfile=f"golden_{label}", tofile=f"actual_{label}"))
    return "".join(diff)


def run_candidate(bin_path: Path, apk_path: Path, command: str, args: list, output_file: Path = None):
    cmd = [str(bin_path), command, str(apk_path), *args]
    if output_file:
        cmd.extend(["-o", str(output_file)])

    res = subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True)
    is_debug = "--debug" in args
    return res.returncode, clean_cli_output(res.stdout, is_debug), res.stderr


def resolve_corpus_apk(cname: str, corpus_dir: Path) -> Path:
    candidates = [
        corpus_dir / f"fixture_{cname}.apk",
        corpus_dir / f"reference_{cname}.apk",
        corpus_dir / f"{cname}.apk",
        ROOT / "Ads Solution June.apk" if cname == "ads_solution" else None,
        ROOT / "tests" / "fixtures" / "reference-workload.zip" if cname == "workload" else None,
    ]
    for c in candidates:
        if c is not None and c.exists():
            return c
    return corpus_dir / f"fixture_{cname}.apk"


def check_conformance(bin_path: Path, golden_dir: Path, corpus_dir: Path, check_dex: bool = False):
    manifest_path = golden_dir / "manifest.json"
    if not manifest_path.exists():
        print(f"Error: Golden manifest not found at {manifest_path}. Run gen_golden.py first.", file=sys.stderr)
        sys.exit(1)

    with open(manifest_path, "r", encoding="utf-8") as f:
        cases = json.load(f)

    print(f"Running conformance checks for binary: {bin_path}")
    print(f"Total golden cases to verify: {len(cases)}\n")

    passed = 0
    failed = 0
    first_divergence = None

    for idx, case in enumerate(cases):
        target_dir = golden_dir / case["path"]
        meta = case["meta"]
        qid = meta["query_id"]
        cname = meta["corpus_name"]
        command = meta["command"]
        args = meta["args"]

        expected_stdout = (target_dir / "stdout.txt").read_text(encoding="utf-8")
        expected_stderr = (target_dir / "stderr.txt").read_text(encoding="utf-8")
        expected_rc = int((target_dir / "exit_code.txt").read_text(encoding="utf-8").strip())

        apk_file = resolve_corpus_apk(cname, corpus_dir)
        if not apk_file.exists():
            print(f"[{idx+1}/{len(cases)}] SKIP: Corpus APK for '{cname}' not found at {apk_file}")
            continue
        actual_apk_sha = hashlib.sha256(apk_file.read_bytes()).hexdigest()
        if actual_apk_sha != meta["apk_sha256"]:
            failed += 1
            print(f"[{idx+1}/{len(cases)}] FAIL: {qid} on {cname} (corpus APK hash mismatch: "
                  f"golden was made from {meta['apk_sha256'][:16]}, file is {actual_apk_sha[:16]})")
            if first_divergence is None:
                first_divergence = {
                    "case": case,
                    "target_dir": str(target_dir),
                    "divergences": ["Corpus APK does not match the one the golden was generated from; regenerate goldens or restore the corpus."],
                }
            continue

        temp_out = target_dir / "candidate_output.tmp"
        rc, stdout, stderr = run_candidate(bin_path, apk_file, command, args, output_file=temp_out if (target_dir / "output.file").exists() else None)

        divergences = []
        if rc != expected_rc:
            divergences.append(f"Exit code mismatch: expected {expected_rc}, got {rc}")

        if stdout != expected_stdout:
            divergences.append(f"Stdout divergence:\n{diff_text(expected_stdout, stdout, 'stdout')}")

        if stderr != expected_stderr:
            divergences.append(f"Stderr divergence:\n{diff_text(expected_stderr, stderr, 'stderr')}")

        if (target_dir / "output.file").exists() and temp_out.exists():
            expected_out_file = (target_dir / "output.file").read_text(encoding="utf-8", errors="replace")
            actual_out_file = temp_out.read_text(encoding="utf-8", errors="replace")
            if actual_out_file != expected_out_file:
                divergences.append(f"Output file mismatch:\n{diff_text(expected_out_file, actual_out_file, 'output_file')}")
            temp_out.unlink(missing_ok=True)

        # Level 2 check: rebuilt DEX byte / SHA comparison (when candidate supports getdex or --dump-dex)
        if check_dex and (target_dir / "rebuilt.dex").exists():
            expected_dex_sha = (target_dir / "rebuilt.dex.sha256").read_text(encoding="utf-8").strip()
            # If the candidate supports emitting rebuilt DEX, verify it here
            cand_dex_path = target_dir / "candidate_rebuilt.dex"
            if cand_dex_path.exists():
                actual_dex_sha = hashlib.sha256(cand_dex_path.read_bytes()).hexdigest()
                if actual_dex_sha != expected_dex_sha:
                    divergences.append(f"Level 2 Rebuilt DEX SHA mismatch: expected {expected_dex_sha}, got {actual_dex_sha}")
                cand_dex_path.unlink(missing_ok=True)

        if divergences:
            failed += 1
            print(f"[{idx+1}/{len(cases)}] FAIL: {qid} on {cname}")
            if first_divergence is None:
                first_divergence = {
                    "case": case,
                    "target_dir": str(target_dir),
                    "divergences": divergences,
                }
        else:
            passed += 1
            print(f"[{idx+1}/{len(cases)}] PASS: {qid} on {cname}")

    print("\n" + "=" * 50)
    print(f"Conformance Results: {passed} passed, {failed} failed (Total: {passed + failed})")
    print("=" * 50)

    if first_divergence:
        print("\nFIRST DIVERGENCE DETAILS:")
        print(f"Case: {first_divergence['case']['meta']['query_id']} on {first_divergence['case']['meta']['corpus_name']}")
        print(f"Golden path: {first_divergence['target_dir']}")
        for div in first_divergence["divergences"]:
            print(div)
        sys.exit(1)

    print("\nAll checked conformance cases passed byte-for-byte!")
    sys.exit(0)


def main():
    parser = argparse.ArgumentParser(description="Check candidate binary against conformance goldens.")
    parser.add_argument("--bin", required=True, help="Path to candidate binary to test")
    parser.add_argument("--golden-dir", default=str(ROOT / "rust" / "conformance" / "golden"), help="Path to golden directory")
    parser.add_argument("--corpus-dir", default=str(ROOT / "rust" / "conformance" / "corpus"), help="Path to corpus directory")
    parser.add_argument("--check-dex", action="store_true", help="Also verify Level 2 rebuilt DEX SHA256")
    args = parser.parse_args()

    check_conformance(Path(args.bin), Path(args.golden_dir), Path(args.corpus_dir), check_dex=args.check_dex)


if __name__ == "__main__":
    main()
