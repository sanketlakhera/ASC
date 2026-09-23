#!/usr/bin/env python3
"""Conformance test runner: Check candidate Rust binary against golden oracle files.

Usage:
  python rust/conformance/check.py --bin path/to/asc [--golden-dir golden] [--corpus-dir corpus]
"""
import argparse
import difflib
import gzip
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


def diff_json(expected, actual, path=""):
    if type(expected) != type(actual):
        return f"Type mismatch at {path or '<root>'}: expected {type(expected).__name__}, got {type(actual).__name__}"
    if isinstance(expected, dict):
        exp_keys = set(expected.keys())
        act_keys = set(actual.keys())
        if exp_keys != act_keys:
            missing = exp_keys - act_keys
            extra = act_keys - exp_keys
            msg = []
            if missing:
                msg.append(f"missing {sorted(missing)}")
            if extra:
                msg.append(f"extra {sorted(extra)}")
            return f"Key mismatch at {path or '<root>'}: {', '.join(msg)}"
        for k in sorted(exp_keys):
            sub_path = f"{path}.{k}" if path else str(k)
            err = diff_json(expected[k], actual[k], sub_path)
            if err:
                return err
        return None
    elif isinstance(expected, list):
        if len(expected) != len(actual):
            return f"Length mismatch at {path or '<root>'}: expected {len(expected)}, got {len(actual)}"
        for i, (e_item, a_item) in enumerate(zip(expected, actual)):
            sub_path = f"{path}[{i}]"
            err = diff_json(e_item, a_item, sub_path)
            if err:
                return err
        return None
    else:
        if expected != actual:
            return f"Value mismatch at {path or '<root>'}: expected {repr(expected)}, got {repr(actual)}"
        return None


def check_primitives(bin_path: Path, golden_dir: Path, corpus_dir: Path):
    print(f"Running primitive conformance checks for binary: {bin_path}")

    # Find all golden directories with primitives
    golden_apk_hashes = sorted([
        p.parent.name for p in golden_dir.glob("*/primitives") if p.is_dir()
    ])

    if not golden_apk_hashes:
        print(f"Error: No primitive goldens found in {golden_dir}. Run gen_golden.py first.", file=sys.stderr)
        sys.exit(1)

    # Build corpus mapping by apk sha256 prefix
    corpus_map = {}
    for apk_file in list(corpus_dir.glob("*.apk")) + [ROOT / "Ads Solution June.apk"]:
        if apk_file.exists():
            h = hashlib.sha256(apk_file.read_bytes()).hexdigest()[:16]
            corpus_map[h] = apk_file

    passed = 0
    failed = 0
    first_divergence = None

    for idx, apk_hash in enumerate(golden_apk_hashes):
        prim_dir = golden_dir / apk_hash / "primitives"
        expected_file = prim_dir / "primitives.json.gz"
        if not expected_file.exists():
            print(f"[{idx+1}/{len(golden_apk_hashes)}] SKIP: {apk_hash} (missing primitives.json.gz)")
            continue

        apk_file = corpus_map.get(apk_hash)
        if not apk_file or not apk_file.exists():
            print(f"[{idx+1}/{len(golden_apk_hashes)}] SKIP: Corpus APK for hash {apk_hash} not found")
            continue

        # Run candidate
        if str(bin_path).endswith(".py"):
            cmd = [sys.executable, str(bin_path), str(apk_file)]
        else:
            cmd = [str(bin_path), "dump-primitives", str(apk_file)]

        res = subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True)
        if res.returncode != 0:
            failed += 1
            divergence = f"Candidate process exited with {res.returncode}. Stderr:\n{res.stderr}"
            print(f"[{idx+1}/{len(golden_apk_hashes)}] FAIL: primitives for {apk_file.name} (exit code {res.returncode})")
            if first_divergence is None:
                first_divergence = {
                    "apk": apk_file.name,
                    "apk_hash": apk_hash,
                    "divergence": divergence,
                }
            continue

        try:
            actual_json = json.loads(res.stdout)
        except json.JSONDecodeError as e:
            failed += 1
            divergence = f"Failed to parse candidate JSON output: {e}\nRaw output:\n{res.stdout[:500]}"
            print(f"[{idx+1}/{len(golden_apk_hashes)}] FAIL: primitives for {apk_file.name} (invalid JSON)")
            if first_divergence is None:
                first_divergence = {
                    "apk": apk_file.name,
                    "apk_hash": apk_hash,
                    "divergence": divergence,
                }
            continue

        expected_json = json.loads(gzip.decompress(expected_file.read_bytes()).decode("utf-8"))
        divergence = diff_json(expected_json, actual_json)

        if divergence:
            failed += 1
            print(f"[{idx+1}/{len(golden_apk_hashes)}] FAIL: primitives for {apk_file.name}")
            if first_divergence is None:
                first_divergence = {
                    "apk": apk_file.name,
                    "apk_hash": apk_hash,
                    "divergence": divergence,
                }
        else:
            passed += 1
            print(f"[{idx+1}/{len(golden_apk_hashes)}] PASS: primitives for {apk_file.name}")

    print("\n" + "=" * 50)
    print(f"Primitive Conformance Results: {passed} passed, {failed} failed (Total: {passed + failed})")
    print("=" * 50)

    if first_divergence:
        print("\nFIRST DIVERGENCE DETAILS:")
        print(f"APK: {first_divergence['apk']} (hash: {first_divergence['apk_hash']})")
        print(first_divergence["divergence"])
        sys.exit(1)

    print("\nAll checked primitive goldens passed key-for-key!")
    sys.exit(0)


def main():
    parser = argparse.ArgumentParser(description="Check candidate binary against conformance goldens.")
    parser.add_argument("--bin", required=True, help="Path to candidate binary to test")
    parser.add_argument("--golden-dir", default=str(ROOT / "rust" / "conformance" / "golden"), help="Path to golden directory")
    parser.add_argument("--corpus-dir", default=str(ROOT / "rust" / "conformance" / "corpus"), help="Path to corpus directory")
    parser.add_argument("--check-dex", action="store_true", help="Also verify Level 2 rebuilt DEX SHA256")
    parser.add_argument("--primitives", action="store_true", help="Verify Level 3 primitive dumps")
    args = parser.parse_args()

    if args.primitives:
        check_primitives(Path(args.bin), Path(args.golden_dir), Path(args.corpus_dir))
    else:
        check_conformance(Path(args.bin), Path(args.golden_dir), Path(args.corpus_dir), check_dex=args.check_dex)


if __name__ == "__main__":
    main()

