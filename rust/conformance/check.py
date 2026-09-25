#!/usr/bin/env python3
"""Conformance test runner: Check candidate Rust binary against golden oracle files.

Usage:
  python rust/conformance/check.py --bin path/to/asc [--golden-dir golden] [--corpus-dir corpus]
  python rust/conformance/check.py --primitives --bin path/to/asc   # M1 primitive dumps
  python rust/conformance/check.py --findrefs --bin path/to/asc     # M2 findrefs stage dumps
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
# findrefs --debug lines carry timings and pids; keep their shape, not their values
TIMING_LINE_REGEX = re.compile(r"^\[(?:DEBUG|APK)\].*$", re.MULTILINE)
UNSUPPORTED_SYNTAX = "Error: unsupported pattern syntax"


def _text(raw: bytes) -> str:
    # bytes as written, no newline translation: subprocess text mode would turn
    # every "\r" into "\n" and hide a real difference
    return raw.decode("utf-8", "surrogateescape")


def clean_cli_output(text: str, is_debug: bool = False, command: str = "") -> str:
    if not is_debug:
        return text
    if command == "findrefs":
        return TIMING_LINE_REGEX.sub(lambda m: re.sub(r"\d+", "N", m.group(0)), text)
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

    res = subprocess.run(cmd, cwd=ROOT, capture_output=True)
    # any abbreviation argparse accepts for --debug (--deb, --de, ...)
    is_debug = any(len(a) > 3 and "--debug".startswith(a) for a in args)
    return res.returncode, clean_cli_output(_text(res.stdout), is_debug, command), _text(res.stderr)


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


def check_conformance(bin_path: Path, golden_dir: Path, corpus_dir: Path, check_dex: bool = False,
                      only: str = None):
    manifest_path = golden_dir / "manifest.json"
    if not manifest_path.exists():
        print(f"Error: Golden manifest not found at {manifest_path}. Run gen_golden.py first.", file=sys.stderr)
        sys.exit(1)

    with open(manifest_path, "r", encoding="utf-8") as f:
        cases = json.load(f)
    if only:
        cases = [c for c in cases if c["meta"]["command"] == only]

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

        expected_stdout = _text((target_dir / "stdout.txt").read_bytes())
        expected_stderr = _text((target_dir / "stderr.txt").read_bytes())
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

        # Documented divergences (gen_golden.findrefs_queries): the golden's
        # expectation is narrowed, never dropped.
        if meta.get("rust_expect") == "unsupported_syntax":
            expected_rc, expected_stdout = 1, ""
            if stderr.startswith(UNSUPPORTED_SYNTAX) and stderr.endswith("\n") and stderr.count("\n") == 1:
                expected_stderr = stderr
            else:
                expected_stderr = UNSUPPORTED_SYNTAX + ": <pattern error>\n"
        elif meta.get("error_prefix_only") and expected_stderr.startswith("Error: ") and stderr.startswith("Error: "):
            expected_stderr = stderr
        elif meta.get("exit_code_only"):
            expected_stdout, expected_stderr = stdout, stderr

        divergences = []
        if rc != expected_rc:
            divergences.append(f"Exit code mismatch: expected {expected_rc}, got {rc}")

        if stdout != expected_stdout:
            divergences.append(f"Stdout divergence:\n{diff_text(expected_stdout, stdout, 'stdout')}")

        if stderr != expected_stderr:
            divergences.append(f"Stderr divergence:\n{diff_text(expected_stderr, stderr, 'stderr')}")

        if meta.get("rust_expect") or meta.get("exit_code_only"):
            temp_out.unlink(missing_ok=True)
        elif (target_dir / "output.file").exists() and temp_out.exists():
            expected_out_file = _text((target_dir / "output.file").read_bytes())
            actual_out_file = _text(temp_out.read_bytes())
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


def normalize_findrefs_divergences(expected, actual):
    """Queries whose pattern only Python accepts (dump_findrefs.PYTHON_ONLY_PATTERNS)
    must fail in the candidate with an unsupported-syntax error once Python got
    as far as compiling it (its record has "located"); both records are then
    reduced to that fact before the tree comparison. When Python failed first
    (a corrupt string table), the records must match as they are."""
    for e_dex, a_dex in zip(expected.get("dex", []), actual.get("dex", [])):
        e_queries, a_queries = e_dex.get("queries"), a_dex.get("queries")
        if not isinstance(e_queries, list) or not isinstance(a_queries, list):
            continue
        for i, (e_q, a_q) in enumerate(zip(e_queries, a_queries)):
            if e_q.get("expect_rust") != "unsupported_syntax":
                continue
            if "located" not in e_q:
                del e_q["expect_rust"]
                continue
            refused = str(a_q.get("error", "")).startswith("unsupported pattern syntax")
            e_queries[i] = {"kind": e_q["kind"], "query": e_q["query"], "unsupported_syntax": True}
            a_queries[i] = {"kind": a_q.get("kind"), "query": a_q.get("query"), "unsupported_syntax": refused}


def check_findrefs(bin_path: Path, golden_dir: Path, corpus_dir: Path):
    print(f"Running findrefs stage conformance checks for binary: {bin_path}")
    golden_apk_hashes = sorted(p.parent.name for p in golden_dir.glob("*/findrefs") if p.is_dir())
    if not golden_apk_hashes:
        print(f"Error: No findrefs goldens found in {golden_dir}. Run gen_golden.py first.", file=sys.stderr)
        sys.exit(1)

    corpus_map = {}
    for apk_file in list(corpus_dir.glob("*.apk")) + [ROOT / "Ads Solution June.apk"]:
        if apk_file.exists():
            corpus_map[hashlib.sha256(apk_file.read_bytes()).hexdigest()[:16]] = apk_file

    passed = failed = 0
    first_divergence = None
    total = len(golden_apk_hashes)
    for idx, apk_hash in enumerate(golden_apk_hashes):
        expected_file = golden_dir / apk_hash / "findrefs" / "findrefs.json.gz"
        apk_file = corpus_map.get(apk_hash)
        if not expected_file.exists() or apk_file is None:
            print(f"[{idx+1}/{total}] SKIP: {apk_hash} (golden or corpus APK missing)")
            continue
        if str(bin_path).endswith(".py"):
            cmd = [sys.executable, str(bin_path), str(apk_file)]
        else:
            cmd = [str(bin_path), "dump-findrefs", str(apk_file)]
        res = subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True)
        divergence = None
        if res.returncode != 0:
            divergence = f"Candidate process exited with {res.returncode}. Stderr:\n{res.stderr}"
        else:
            try:
                actual_json = json.loads(res.stdout)
            except json.JSONDecodeError as e:
                divergence = f"Failed to parse candidate JSON output: {e}\nRaw output:\n{res.stdout[:500]}"
            else:
                expected_json = json.loads(gzip.decompress(expected_file.read_bytes()).decode("utf-8"))
                normalize_findrefs_divergences(expected_json, actual_json)
                divergence = diff_json(expected_json, actual_json)
        if divergence:
            failed += 1
            print(f"[{idx+1}/{total}] FAIL: findrefs stages for {apk_file.name}")
            if first_divergence is None:
                first_divergence = (apk_file.name, apk_hash, divergence)
        else:
            passed += 1
            print(f"[{idx+1}/{total}] PASS: findrefs stages for {apk_file.name}")

    print("\n" + "=" * 50)
    print(f"Findrefs Stage Conformance Results: {passed} passed, {failed} failed (Total: {passed + failed})")
    print("=" * 50)
    if first_divergence:
        name, apk_hash, divergence = first_divergence
        print("\nFIRST DIVERGENCE DETAILS:")
        print(f"APK: {name} (hash: {apk_hash})")
        print(divergence)
        sys.exit(1)
    print("\nAll checked findrefs stage goldens passed key-for-key!")
    sys.exit(0)


def main():
    parser = argparse.ArgumentParser(description="Check candidate binary against conformance goldens.")
    parser.add_argument("--bin", required=True, help="Path to candidate binary to test")
    parser.add_argument("--golden-dir", default=str(ROOT / "rust" / "conformance" / "golden"), help="Path to golden directory")
    parser.add_argument("--corpus-dir", default=str(ROOT / "rust" / "conformance" / "corpus"), help="Path to corpus directory")
    parser.add_argument("--check-dex", action="store_true", help="Also verify Level 2 rebuilt DEX SHA256")
    parser.add_argument("--primitives", action="store_true", help="Verify Level 3 primitive dumps")
    parser.add_argument("--findrefs", action="store_true", help="Verify Level 3 findrefs stage dumps")
    parser.add_argument("--only", choices=("findrefs", "getclass", "getmanifest"),
                        help="CLI goldens of one command only (the Rust CLI grows a command per milestone)")
    args = parser.parse_args()

    if args.findrefs:
        check_findrefs(Path(args.bin), Path(args.golden_dir), Path(args.corpus_dir))
    elif args.primitives:
        check_primitives(Path(args.bin), Path(args.golden_dir), Path(args.corpus_dir))
    else:
        check_conformance(Path(args.bin), Path(args.golden_dir), Path(args.corpus_dir), check_dex=args.check_dex,
                          only=args.only)


if __name__ == "__main__":
    main()

