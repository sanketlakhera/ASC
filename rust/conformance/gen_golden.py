#!/usr/bin/env python3
"""Conformance test harness: Golden generator for Droid ASC.

Runs the Python oracle against the corpus and generates multi-tier golden records:
  Level 1 (CLI): Raw stdout, stderr, exit_code, and -o output files.
  Level 2 (DEX): Rebuilt minimal DEX bytes and SHA-256 for getclass queries.
  Level 3 (stages): per corpus APK, primitives/primitives.json.gz (M1,
                    dump_primitives.py) and findrefs/findrefs.json.gz (M2,
                    dump_findrefs.py).

Note: stage dumps for DAD AST and SSA forms are scheduled for M5.

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

from dex_fixture import (make_dex, make_static_field_dex, make_dex041_container, make_axml, DEFAULT_STRINGS,
                         make_slow_insns_overrun_dex, make_fast_bad_string_ids_dex)
from droidasc.asc_core.utils.mutf8 import encode_mutf8
from droidasc.asc_core.core.dex.dex_manager import DexManager
from droidasc.asc_client.apk_handler import ApkHandler
from dump_primitives import dump_apk_primitives
from dump_findrefs import dump_apk_findrefs
from droidasc.asc_core.utils.tinydex import DEX, DexField, DexMethod
try:
    import androguard
except Exception:
    androguard = None

DEBUG_REGEX = re.compile(r"^\[DEBUG\].*$\n?", re.MULTILINE)
SEP_REGEX = re.compile(r"^-{40,}.*$\n?", re.MULTILINE)
# findrefs --debug lines carry timings and pids; keep their shape, not their values
TIMING_LINE_REGEX = re.compile(r"^\[(?:DEBUG|APK)\].*$", re.MULTILINE)


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
        # rstrip, not strip: the first line's status column may start with a
        # space (" M path"), and stripping it shifts the path by one character
        status = subprocess.check_output(
            ["git", "-C", str(ROOT), "status", "--porcelain"], text=True
        ).rstrip()
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

    # 8. findrefs error order across entries (M2 F3). Entry order is ascending
    # compressed size; one failing entry is slow (48 MB of zeros to inflate),
    # the other fails at once. The error printed is the first in entry order.
    for cname, entries in (
        ("error_order_slow_first", [make_slow_insns_overrun_dex(), make_fast_bad_string_ids_dex()]),
        ("error_order_fast_first", [make_fast_bad_string_ids_dex(padding=8 << 10), make_slow_insns_overrun_dex()]),
    ):
        apk_order = corpus_dir / f"fixture_{cname}.apk"
        with zipfile.ZipFile(apk_order, "w") as zf:
            _write_entry(zf, "classes.dex", make_dex(), zipfile.ZIP_DEFLATED)
            for n, data in enumerate(entries, 2):
                _write_entry(zf, f"classes{n}.dex", data, zipfile.ZIP_DEFLATED)
        corpus[cname] = apk_order

    # 9. An APK without DEX entries: findrefs prints nothing and never starts
    # a worker pool, so even --threads 0 exits 0.
    apk_no_dex = corpus_dir / "fixture_no_dex.apk"
    with zipfile.ZipFile(apk_no_dex, "w") as zf:
        _write_entry(zf, "AndroidManifest.xml", make_axml(), zipfile.ZIP_STORED)
    corpus["no_dex"] = apk_no_dex

    # Fuzz findings are committed as-is (not generated): one per parity bug class.
    for apk in sorted(corpus_dir.glob("fixture_fuzz_*.apk")):
        corpus[apk.stem.removeprefix("fixture_")] = apk

    return corpus


def workload_samples(corpus: dict):
    """Method 0 and field 0 of the workload DEX as (class descriptor, name),
    the samples the reference script queries with; None without the workload."""
    if "workload" not in corpus:
        return None
    with zipfile.ZipFile(corpus["workload"]) as zf:
        dex = DEX.parse(memoryview(zf.read("classes.dex")), "classes.dex")
    method, field = DexMethod(dex, 0), DexField(dex, 0)
    return (method.cls.fullname, method.name), (field.cls.fullname, field.name)


def findrefs_queries(corpus: dict):
    """findrefs CLI goldens (M2 plan section 3.2).

    Optional per-query flags, recorded in meta.json and honoured by check.py:
      error_prefix_only  the Python message is re.error text: compare the exit
                         code, stdout and the "Error: " prefix only
      exit_code_only     an argparse usage error (usage text is M6)
      rust_expect        "unsupported_syntax": Python accepts the pattern, the
                         Rust engine refuses it with "Error: unsupported
                         pattern syntax" (plan section 5, decision R)
    """
    def q(qid, corpus_names, args, **flags):
        return {"id": f"findrefs_{qid}", "command": "findrefs", "corpus": corpus_names, "args": args, **flags}

    queries = []
    samples = workload_samples(corpus)
    if samples is not None:
        (m_cls, m_name), (f_cls, f_name) = samples
        m_dotted = m_cls[1:-1].replace("/", ".")
        queries += [
            # the reference script's queries (reference-baseline.json counts)
            q("ref_string_create", ["workload"], ["string", "create"]),
            q("ref_method_view", ["workload"], ["method", "view"]),
            q("ref_method_precise_class", ["workload"], ["method", "--class", m_cls]),
            q("ref_method_precise_class_name", ["workload"], ["method", m_name, "--class", m_cls]),
            q("ref_method_fuzzy_class", ["workload"], ["method", "--class", "AccessibilityServiceInfo", "--fuzzy-class"]),
            q("ref_method_fuzzy_class_name", ["workload"],
              ["method", m_name, "--class", "AccessibilityServiceInfo", "--fuzzy-class"]),
            q("ref_field_action", ["workload"], ["field", "action"]),
            q("ref_field_precise_class", ["workload"], ["field", "--class", f_cls]),
            q("ref_field_precise_class_name", ["workload"], ["field", f_name, "--class", f_cls]),
            q("ref_field_fuzzy_class", ["workload"], ["field", "--class", "Notification", "--fuzzy-class"]),
            q("ref_field_fuzzy_class_name", ["workload"], ["field", f_name, "--class", "Notification", "--fuzzy-class"]),
            q("ref_type_view", ["workload"], ["type", "View"]),
            # class-name normalisation on real classes
            q("norm_workload_dotted", ["workload"], ["method", "--class", m_dotted]),
            q("norm_workload_fuzzy_dotted", ["workload"], ["method", "--class", m_dotted, "--fuzzy-class"]),
            # a precise class name is matched as a literal substring, not a regex
            q("precise_name_is_literal", ["workload"], ["method", m_name[:1] + "." + m_name[2:], "--class", m_cls]),
            q("re_workload_final_char", ["workload"], ["string", "create."]),
        ]

    synthetic = ["stored", "multidex"]
    queries += [
        # class-name normalisation (cli._format_class_name / _normalize_class_query)
        q("norm_dotted", synthetic, ["method", "--class", "example.Test"]),
        q("norm_descriptor", synthetic, ["method", "--class", "Lexample/Test;"]),
        q("norm_leading_l", synthetic, ["method", "--class", "Lexample.Test"]),
        q("norm_fuzzy_package", synthetic, ["method", "--class", "example", "--fuzzy-class"]),
        q("norm_fuzzy_dotted", synthetic, ["method", "--class", "example.Test", "--fuzzy-class"]),
        q("norm_field_dotted", ["multidex"], ["field", "--class", "example.Statics"]),
        q("norm_field_fuzzy_name", ["multidex"], ["field", "SEC", "--class", "Statics", "--fuzzy-class"]),
        # regex surface
        q("re_wildcard", ["stored", "workload"], ["string", "tok.n"]),
        q("re_anchor", ["stored", "workload"], ["string", "^tok"]),
        q("re_icase", ["stored", "workload"], ["string", "(?i)TOKEN"]),
        q("re_class", ["stored", "workload"], ["string", "[a-c]reate"]),
        q("re_final_terminator", ["stored", "workload"], ["string", "token."]),
        q("re_every_string", ["stored", "multidex"], ["string", "."]),
        q("re_alternation", ["stored", "multidex"], ["string", "first|token"]),
        q("re_type_wildcard", ["stored", "multidex"], ["type", "example.Test"]),
        q("re_literal_brace", ["stored", "workload"], ["string", "a{"]),
        q("re_python_braces", ["stored", "workload"], ["string", "crea{1,}te|ma{,1}x{}|{1|tok{,2}en"]),
        # can match empty and prefers the empty option: CPython's finditer then
        # retries a non-empty match at the same position, regex cannot
        q("re_empty_preferring", ["stored"], ["string", "|token"], rust_expect="unsupported_syntax"),
        q("re_lookbehind", ["stored", "workload"], ["string", "(?<=t)oken"], rust_expect="unsupported_syntax"),
        q("re_possessive", ["stored"], ["string", "to++ken"], rust_expect="unsupported_syntax"),
        q("re_unclosed", ["stored", "workload"], ["string", "(unclosed"], error_prefix_only=True),
        # MUTF-8
        q("mutf8_non_ascii", ["mutf8"], ["string", "\u00e9"]),
        q("mutf8_emoji", ["mutf8"], ["string", "\U0001F600"]),
        q("mutf8_emoji_class", ["mutf8"], ["method", "--class", "L\U0001F600;"]),
        # DEX 041 container: every locator, not only strings
        q("dex041_method", ["dex041"], ["method", "first"]),
        q("dex041_method_class", ["dex041"], ["method", "--class", "example.Test"]),
        q("dex041_type", ["dex041"], ["type", "Lexample/Test;"]),
        q("dex041_every_string", ["dex041"], ["string", "."]),
        # error contract
        q("err_empty_member", ["stored"], ["method"]),
        q("err_empty_field_class", ["stored"], ["field", "--class", ""]),
        q("err_empty_string", ["stored"], ["string", ""]),
        q("err_threads_zero", ["stored", "no_dex"], ["--threads", "0", "string", "token"]),
        q("err_threads_negative", ["stored"], ["--threads", "-1", "string", "token"]),
        q("err_error_order", ["error_order_slow_first", "error_order_fast_first"], ["string", "token"]),
        q("err_lazy_insn_map", ["fuzz_insns_hang", "fuzz_insns_overrun"], ["string", "zzz_nomatch"]),
        q("err_corrupt", sorted(c for c in corpus if c.startswith(("corrupt_", "fuzz_"))), ["string", "token"]),
        q("no_dex_entries", ["no_dex"], ["string", "token"]),
        # argparse grammar (usage text itself is M6)
        # --thr is ambiguous: it prefixes both --threads and --thread
        q("argparse_ambiguous_prefix", ["stored"], ["--thr", "2", "string", "token"], exit_code_only=True),
        q("argparse_unique_prefix", ["stored"], ["--deb", "method", "--cl", "example", "--fuzzy"]),
        # an attached short value; the -o output.file appended after it wins
        q("argparse_short_attached", ["stored"], ["string", "-o/dev/null", "tok.n"]),
        q("argparse_double_dash", ["stored"], ["string", "--", "-tok"], no_output_file=True),
        q("argparse_bad_int", ["stored"], ["--threads", "two", "string", "token"], exit_code_only=True),
        q("argparse_bad_choice", ["stored"], ["strings", "token"], exit_code_only=True),
        q("argparse_equals", ["stored"], ["--threads=2", "string", "token"]),
        q("argparse_thread_alias", ["stored"], ["--thread", "2", "string", "token"]),
        q("argparse_debug_after_leaf", ["stored"], ["string", "token", "--debug"], exit_code_only=True),
        q("argparse_missing_value", ["stored"], ["string"], exit_code_only=True),
        # --debug: timing lines keep their shape, numbers normalised
        q("debug_single_entry", ["stored"], ["--debug", "--threads", "1", "string", "token"]),
        q("debug_no_entries", ["no_dex"], ["--debug", "string", "token"]),
        # a large real APK (local only)
        q("ads_string_create", ["ads_solution"], ["string", "create"]),
        q("ads_method_oncreate", ["ads_solution"], ["method", "onCreate"]),
        q("ads_field_fuzzy_class", ["ads_solution"], ["field", "--class", "Notification", "--fuzzy-class"]),
    ]
    return queries


def define_queries(corpus: dict):
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
        # corrupt code_item: insns past the end hung findrefs (M0 sweep, 44 cases)
        # and leaked struct.error from androguard through getclass
        {
            "id": "findrefs_method_corrupt_insns",
            "command": "findrefs",
            "corpus": ["fuzz_insns_overrun", "fuzz_insns_hang"],
            "args": ["method", "first"],
        },
        {
            "id": "getclass_corrupt_insns",
            "command": "getclass",
            "corpus": ["fuzz_insns_overrun"],
            "args": ["Lexample/Test;"],
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
    ] + findrefs_queries(corpus)


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


def run_oracle_cli(apk_path: Path, command: str, args: list, output_file: Path = None):
    cmd = [sys.executable, str(ROOT / "main.py"), command, str(apk_path), *args]
    if output_file:
        cmd.extend(["-o", str(output_file)])

    res = subprocess.run(cmd, cwd=ROOT, capture_output=True)
    # any abbreviation argparse accepts for --debug (--deb, --de, ...)
    is_debug = any(len(a) > 3 and "--debug".startswith(a) for a in args)
    return res.returncode, clean_cli_output(_text(res.stdout), is_debug, command), _text(res.stderr)


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
    queries = define_queries(corpus)

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

            # -o goes last, so a query ending in "--" arguments runs without it
            out_flag_file = None if q.get("no_output_file") else target_dir / "output.file"
            rc, stdout, stderr = run_oracle_cli(apk_path, cmd_name, args, output_file=out_flag_file)

            (target_dir / "stdout.txt").write_bytes(stdout.encode("utf-8", "surrogateescape"))
            (target_dir / "stderr.txt").write_bytes(stderr.encode("utf-8", "surrogateescape"))
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
            for flag in ("error_prefix_only", "exit_code_only", "rust_expect"):
                if flag in q:
                    meta[flag] = q[flag]
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

    # Level 3 (M2): findrefs stage dump for every corpus APK
    print("\nGenerating Level 3 findrefs stage goldens for corpus APKs...")
    for cname, apk_path in corpus.items():
        apk_hash = sha256_file(apk_path)[:16]
        fr_dir = output_dir / apk_hash / "findrefs"
        fr_dir.mkdir(parents=True, exist_ok=True)
        payload = json.dumps(dump_apk_findrefs(apk_path), indent=2, sort_keys=True).encode("utf-8")
        with open(fr_dir / "findrefs.json.gz", "wb") as raw:
            with gzip.GzipFile(filename="findrefs.json", mode="wb", fileobj=raw, compresslevel=9, mtime=0) as gz:
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
