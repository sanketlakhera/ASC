#!/usr/bin/env python3
"""Conformance test harness: Golden generator for Droid ASC.

Runs the Python oracle against the corpus and generates multi-tier golden records:
  Level 1 (CLI): Raw stdout, stderr, exit_code, and -o output files.
  Level 2 (DEX): Rebuilt minimal DEX bytes and SHA-256 for getclass queries.

Note: Level 3 (Primitive JSON dumps for DAD AST and SSA forms) is scheduled for M5.

Usage:
  uv run --python 3.12 --with "androguard==4.1.3" python rust/conformance/gen_golden.py
"""
import argparse
import gzip
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import struct
import subprocess
import sys
import zipfile

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))
sys.path.insert(0, str(ROOT / "rust" / "conformance"))

from dex_fixture import make_dex, make_static_field_dex, make_dex041_container, make_axml, DEFAULT_STRINGS
from droidasc.asc_core.utils.mutf8 import encode_mutf8
from droidasc.asc_core.core.dex.dex_manager import DexManager
from droidasc.asc_client.apk_handler import ApkHandler
from dump_primitives import dump_apk_primitives
try:
    import androguard
except Exception:
    androguard = None

DEBUG_REGEX = re.compile(r"^\[DEBUG\].*$\n?", re.MULTILINE)
SEP_REGEX = re.compile(r"^-{40,}.*$\n?", re.MULTILINE)


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
    return h.hexdigest()


def get_git_info(ignore_dirs: tuple = ()) -> tuple:
    """Return (revision, is_dirty, diff_sha256).

    Paths under ``ignore_dirs`` (the generator's own output) do not count as
    dirty, so regenerating goldens on a clean checkout stays clean.
    """
    try:
        rev = subprocess.check_output(
            ["git", "-C", str(ROOT), "describe", "--always", "--dirty"], text=True
        ).strip()
        status = subprocess.check_output(
            ["git", "-C", str(ROOT), "status", "--porcelain"], text=True
        ).strip()
        ignored = tuple(str(Path(d).resolve().relative_to(ROOT)).rstrip("/") + "/" for d in ignore_dirs)
        status_lines = [
            line for line in status.splitlines()
            if not line[3:].startswith(ignored)
        ]
        is_dirty = len(status_lines) > 0
        if not is_dirty:
            rev = rev.removesuffix("-dirty")
        diff_sha = None
        if is_dirty:
            diff_text = subprocess.check_output(
                ["git", "-C", str(ROOT), "diff", "HEAD"], text=True
            )
            diff_sha = hashlib.sha256(diff_text.encode("utf-8")).hexdigest()
        return rev, is_dirty, diff_sha
    except Exception:
        return "unknown", False, None


# Fixed entry timestamp so corpus APKs are byte-reproducible; zipfile would
# otherwise stamp wall-clock time into every entry and change the APK hash
# (and therefore every golden directory name) on each run.
_FIXED_DATE_TIME = (1980, 1, 1, 0, 0, 0)


def _write_entry(zf: zipfile.ZipFile, name: str, data: bytes, compress_type: int):
    info = zipfile.ZipInfo(name, date_time=_FIXED_DATE_TIME)
    info.compress_type = compress_type
    zf.writestr(info, data)


def build_corpus(corpus_dir: Path) -> dict:
    """Creates synthetic APKs, prepares workload APKs, and returns mapping."""
    corpus_dir.mkdir(parents=True, exist_ok=True)
    corpus = {}

    # 1. Stored single DEX APK with valid binary AndroidManifest.xml
    apk_stored = corpus_dir / "fixture_stored.apk"
    with zipfile.ZipFile(apk_stored, "w") as zf:
        _write_entry(zf, "classes.dex", make_dex(), zipfile.ZIP_STORED)
        _write_entry(zf, "AndroidManifest.xml", make_axml(), zipfile.ZIP_STORED)
    corpus["stored"] = apk_stored

    # 2. Deflated multidex APK (with Statics class for field references)
    apk_multidex = corpus_dir / "fixture_multidex.apk"
    with zipfile.ZipFile(apk_multidex, "w") as zf:
        _write_entry(zf, "classes.dex", make_dex(padding=6000), zipfile.ZIP_DEFLATED)
        _write_entry(zf, "classes2.dex", make_dex(), zipfile.ZIP_DEFLATED)
        _write_entry(zf, "classes3.dex", make_static_field_dex(), zipfile.ZIP_DEFLATED)
    corpus["multidex"] = apk_multidex

    # 3. DEX 041 container APK
    apk_dex041 = corpus_dir / "fixture_dex041.apk"
    with zipfile.ZipFile(apk_dex041, "w") as zf:
        _write_entry(zf, "classes.dex", make_dex041_container({}, {"padding": 64}), zipfile.ZIP_DEFLATED)
    corpus["dex041"] = apk_dex041

    # 4. MUTF-8 / Non-BMP / NUL string fixture APK
    apk_mutf8 = corpus_dir / "fixture_mutf8.apk"
    emoji = "\U0001F600"
    emoji_mutf8 = b"\xed\xa0\xbd\xed\xb8\x80"
    strings = DEFAULT_STRINGS[:5] + [
        (b"tok\xc0\x80en" + emoji_mutf8 + b"\xc3\xa9", 9),
        (b"L" + emoji_mutf8 + b";", 4),
    ]
    with zipfile.ZipFile(apk_mutf8, "w") as zf:
        _write_entry(zf, "classes.dex", make_dex(strings=strings), zipfile.ZIP_DEFLATED)
    corpus["mutf8"] = apk_mutf8

    # 5. Workload repacked APK from reference-workload.zip
    workload_zip = ROOT / "tests" / "fixtures" / "reference-workload.zip"
    if workload_zip.exists():
        apk_workload = corpus_dir / "reference_workload.apk"
        with zipfile.ZipFile(workload_zip, "r") as z_in:
            dex_bytes = z_in.read("classes.dex")
        with zipfile.ZipFile(apk_workload, "w") as z_out:
            _write_entry(z_out, "classes.dex", dex_bytes, zipfile.ZIP_DEFLATED)
        corpus["workload"] = apk_workload

    # 6. Real APK: Ads Solution June.apk if present
    ads_apk = ROOT / "Ads Solution June.apk"
    if ads_apk.exists():
        corpus["ads_solution"] = ads_apk

    # 7. Corrupt inputs for error contract verification
    apk_empty = corpus_dir / "fixture_corrupt_empty.apk"
    apk_empty.write_bytes(b"")
    corpus["corrupt_empty"] = apk_empty

    apk_eocd = corpus_dir / "fixture_corrupt_eocd.apk"
    apk_eocd.write_bytes(b"\x00" * 10 + b"PK\x05\x06" + b"\x00" * 10)
    corpus["corrupt_eocd"] = apk_eocd

    apk_cd = corpus_dir / "fixture_corrupt_cd.apk"
    apk_cd.write_bytes(b"PK\x05\x06" + b"\x00" * 8 + struct.pack("<IIH", 1000, 1000, 0))
    corpus["corrupt_cd"] = apk_cd

    apk_corrupt_deflate = corpus_dir / "fixture_corrupt_deflate.apk"
    with zipfile.ZipFile(apk_corrupt_deflate, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        _write_entry(zf, "classes.dex", b"hello world from classes dex", zipfile.ZIP_DEFLATED)
    raw_data = bytearray(apk_corrupt_deflate.read_bytes())
    raw_data[45:55] = b"\xff" * 10
    apk_corrupt_deflate.write_bytes(raw_data)
    corpus["corrupt_deflate"] = apk_corrupt_deflate

    apk_trunc_hdr = corpus_dir / "fixture_corrupt_header.apk"
    with zipfile.ZipFile(apk_trunc_hdr, "w") as zf:
        _write_entry(zf, "classes.dex", b"dex\n035\x00short", zipfile.ZIP_STORED)
    corpus["corrupt_header"] = apk_trunc_hdr

    raw_dex = make_dex()
    for trunc, cname in ((0x70, "corrupt_trunc_70"), (0x90, "corrupt_trunc_90"), (0xB0, "corrupt_trunc_b0")):
        apk_trunc = corpus_dir / f"fixture_{cname}.apk"
        with zipfile.ZipFile(apk_trunc, "w") as zf:
            _write_entry(zf, "classes.dex", raw_dex[:trunc], zipfile.ZIP_STORED)
        corpus[cname] = apk_trunc

    # Fuzz findings are committed as-is (not generated): one per parity bug class.
    for apk in sorted(corpus_dir.glob("fixture_fuzz_*.apk")):
        corpus[apk.stem.removeprefix("fixture_")] = apk

    return corpus


def define_queries():
    """Returns list of query definitions covering synthetic and real corpus."""
    return [
        # findrefs string queries
        {
            "id": "findrefs_string_token",
            "command": "findrefs",
            "corpus": ["stored", "multidex", "dex041", "workload"],
            "args": ["string", "token"],
        },
        # findrefs type queries
        {
            "id": "findrefs_type_test",
            "command": "findrefs",
            "corpus": ["stored", "multidex"],
            "args": ["type", "Lexample/Test;"],
        },
        # findrefs method queries
        {
            "id": "findrefs_method_first",
            "command": "findrefs",
            "corpus": ["stored", "multidex"],
            "args": ["method", "first", "--class", "Lexample/Test;"],
        },
        # findrefs static field query with valid target
        {
            "id": "findrefs_field_static",
            "command": "findrefs",
            "corpus": ["multidex"],
            "args": ["field", "SECOND", "--class", "Lexample/Statics;"],
        },
        # getmanifest queries
        {
            "id": "getmanifest_stored",
            "command": "getmanifest",
            "corpus": ["stored"],
            "args": [],
        },
        {
            "id": "getmanifest_ads",
            "command": "getmanifest",
            "corpus": ["ads_solution"],
            "args": [],
        },
        # getclass queries (synthetic)
        {
            "id": "getclass_example_test",
            "command": "getclass",
            "corpus": ["stored", "multidex"],
            "args": ["Lexample/Test;"],
            "target_class": "Lexample/Test;",
        },
        # getclass query on real APK
        {
            "id": "getclass_ads_google_api",
            "command": "getclass",
            "corpus": ["ads_solution"],
            "args": ["Lcom/google/android/gms/common/GoogleApiAvailability;"],
            "target_class": "Lcom/google/android/gms/common/GoogleApiAvailability;",
        },
    ]


def clean_cli_output(text: str, is_debug: bool = False) -> str:
    if not is_debug:
        return text
    text = DEBUG_REGEX.sub("", text)
    text = SEP_REGEX.sub("", text)
    return text


def run_oracle_cli(apk_path: Path, command: str, args: list, output_file: Path = None):
    cmd = [sys.executable, str(ROOT / "main.py"), command, str(apk_path), *args]
    if output_file:
        cmd.extend(["-o", str(output_file)])

    res = subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True)
    is_debug = "--debug" in args
    return res.returncode, clean_cli_output(res.stdout, is_debug), res.stderr


def generate_goldens(output_dir: Path, corpus_dir: Path, allow_dirty: bool = False):
    git_rev, is_dirty, diff_sha = get_git_info(ignore_dirs=(output_dir, corpus_dir))
    if is_dirty and not allow_dirty:
        print("Error: Working tree is dirty. Commit changes before generating goldens or use --allow-dirty.", file=sys.stderr)
        sys.exit(1)

    androguard_ver = getattr(androguard, "__version__", "unknown")
    py_ver = sys.version.split()[0]
    print(f"Oracle environment: Python {py_ver}, androguard {androguard_ver}")
    print(f"Oracle git revision: {git_rev} (dirty: {is_dirty}, diff SHA: {diff_sha[:8] if diff_sha else 'none'})")

    # Start from an empty golden directory so stale cases from earlier runs
    # (different corpus hash or removed queries) cannot linger.
    if output_dir.exists():
        shutil.rmtree(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    corpus = build_corpus(corpus_dir)
    queries = define_queries()

    manifest_summary = []

    for q in queries:
        qid = q["id"]
        cmd_name = q["command"]
        args = q["args"]

        for cname in q["corpus"]:
            if cname not in corpus:
                print(f"Skipping query '{qid}' on '{cname}' (corpus file not found)")
                continue
            apk_path = corpus[cname]
            apk_hash = sha256_file(apk_path)[:16]
            target_dir = output_dir / apk_hash / qid
            target_dir.mkdir(parents=True, exist_ok=True)

            out_flag_file = target_dir / "output.file"
            rc, stdout, stderr = run_oracle_cli(apk_path, cmd_name, args, output_file=out_flag_file)

            (target_dir / "stdout.txt").write_text(stdout, encoding="utf-8")
            (target_dir / "stderr.txt").write_text(stderr, encoding="utf-8")
            (target_dir / "exit_code.txt").write_text(f"{rc}\n", encoding="utf-8")

            # Level 2: DEX rebuilt bytes for getclass
            if cmd_name == "getclass" and rc == 0:
                dalvik_cls = q.get("target_class")
                hit = ApkHandler(str(apk_path)).get_class_dex(dalvik_cls)
                if hit:
                    dex_name, dex_buf = hit
                    rebuilt_bytes = DexManager(dex_buf).extract_and_rebuild(dalvik_cls)
                    rebuilt_path = target_dir / "rebuilt.dex"
                    rebuilt_path.write_bytes(rebuilt_bytes)
                    sha = hashlib.sha256(rebuilt_bytes).hexdigest()
                    (target_dir / "rebuilt.dex.sha256").write_text(f"{sha}\n", encoding="utf-8")

            # Record full metadata
            meta = {
                "query_id": qid,
                "command": cmd_name,
                "args": args,
                "corpus_name": cname,
                "apk_sha256": sha256_file(apk_path),
                "oracle_git_revision": git_rev,
                "git_dirty": is_dirty,
                "diff_sha256": diff_sha,
                "python_version": sys.version,
                "androguard_version": androguard_ver,
            }
            (target_dir / "meta.json").write_text(json.dumps(meta, indent=2), encoding="utf-8")
            manifest_summary.append({"path": str(target_dir.relative_to(output_dir)), "meta": meta})

    # Level 3: Dump primitives for every corpus APK
    print("\nGenerating Level 3 primitive goldens for corpus APKs...")
    for cname, apk_path in corpus.items():
        apk_hash = sha256_file(apk_path)[:16]
        prim_dir = output_dir / apk_hash / "primitives"
        prim_dir.mkdir(parents=True, exist_ok=True)
        dump = dump_apk_primitives(apk_path)
        # One gzipped file per APK: the plain JSON reaches 250 MB, past GitHub's 100 MB limit.
        # mtime=0 keeps the archive bytes deterministic across regenerations.
        payload = json.dumps(dump, indent=2, sort_keys=True).encode("utf-8")
        with open(prim_dir / "primitives.json.gz", "wb") as raw:
            with gzip.GzipFile(filename="primitives.json", mode="wb", fileobj=raw, compresslevel=9, mtime=0) as gz:
                gz.write(payload)

    (output_dir / "manifest.json").write_text(json.dumps(manifest_summary, indent=2), encoding="utf-8")
    print(f"\nSuccessfully generated {len(manifest_summary)} golden test cases in {output_dir}.")


def main():
    parser = argparse.ArgumentParser(description="Generate golden test files for conformance testing.")
    parser.add_argument("--output-dir", default=str(ROOT / "rust" / "conformance" / "golden"), help="Path to golden directory")
    parser.add_argument("--corpus-dir", default=str(ROOT / "rust" / "conformance" / "corpus"), help="Path to corpus directory")
    parser.add_argument("--allow-dirty", action="store_true", default=False,
                        help="Allow generation on a dirty git tree (goldens then cite a revision that cannot be checked out)")
    args = parser.parse_args()

    generate_goldens(Path(args.output_dir), Path(args.corpus_dir), allow_dirty=args.allow_dirty)


if __name__ == "__main__":
    main()
