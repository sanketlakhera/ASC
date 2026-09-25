#!/usr/bin/env python3
"""Python findrefs oracle, stage by stage, for Droid ASC conformance.

For every logical DEX of an APK, dumps what each findrefs stage computes, so a
mismatch with `asc dump-findrefs` points at a stage rather than an output line:

  string_map   StringLocator region and the string_ids table it searches
  type_map     TypeLocator {str_idx: type ids}
  method_map   MethodLocator {class type idx: ids} and {name str idx: ids}
  field_map    FieldLocator, same shape
  insn_map     InsnLocator walk, bucket table and method_bounds
  queries      per query: located ids, scan offsets and marks, verified
               method ids, and the lines AscHandler.findrefs returns

Each map section is built on its own DEX object, so its error (if any) is its
own. Each query runs on a fresh FindRefManager, in the lazy order the CLI uses.

Encoding: integers as numbers, decoded strings as UTF-16 unit arrays, a failed
section or stage as {"error": message}. Long lists are compacted (see
`compact`) and hashed as their JSON text with no spaces: the canonical form the
Rust side reproduces with serde_json.

Usage: dump_findrefs.py APK > findrefs.json
"""
import argparse
import copy
import hashlib
import json
from pathlib import Path
import re
import struct
import sys

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from droidasc.asc_client import apk_handler
from droidasc.asc_client.asc_handler import AscHandler
from droidasc.asc_client.dex_container import iter_logical_dex_buffers
from droidasc.asc_core.findrefs.findrefs_manager import FindRefManager
from droidasc.asc_core.findrefs.locator.field_locator import FieldLocator
from droidasc.asc_core.findrefs.locator.insn_locator import InsnLocator
from droidasc.asc_core.findrefs.locator.method_locator import MethodLocator
from droidasc.asc_core.findrefs.locator.string_locator import StringLocator
from droidasc.asc_core.findrefs.locator.type_locator import TypeLocator
from droidasc.asc_core.utils.tinydex import DEX, DexField, DexMethod

# Lists up to this length are dumped whole; longer ones as count, hash and head.
COMPACT_LIMIT = 64
COMPACT_HEAD = 16

# Patterns Python's re accepts but the Rust engine refuses (plan section 5,
# decision R): lookaround, backreferences, conditionals, atomic groups,
# possessive repeats. The Rust dump must report an "unsupported pattern
# syntax" error for these; everything else must match. (`a{`, a literal brace
# in Python, is translated exactly and so is an ordinary query.)
PYTHON_ONLY_PATTERNS = ("(?<=t)oken",)

STRING_PATTERNS = ("token", "create", "", ".", "token.", "^L", "(?i)VIEW", "a{", "(?<=t)oken")
TYPE_PATTERNS = ("Lexample/Test;", "View")


def units(s: str) -> list:
    raw = s.encode("utf-16-le", "surrogatepass")
    return list(struct.unpack(f"<{len(raw) >> 1}H", raw))


def canonical(value) -> bytes:
    return json.dumps(value, separators=(",", ":")).encode("ascii")


def sha256(value) -> str:
    return hashlib.sha256(canonical(value)).hexdigest()


def compact(values: list):
    if len(values) <= COMPACT_LIMIT:
        return values
    return {"count": len(values), "sha256": sha256(values), "head": values[:COMPACT_HEAD]}


def error(exc: Exception) -> dict:
    return {"error": str(exc)}


def fresh(buf, name):
    return DEX.parse(memoryview(buf), name)


def dump_string_map(buf, name):
    loc = StringLocator(fresh(buf, name))
    try:
        loc._build_map()
    except Exception as e:
        return error(e)
    off, size = loc.header.strings
    table = sorted((struct.unpack_from("<I", buf, off + 4 * i)[0], i) for i in range(size))
    return {
        "strdata_start": loc.strdata_start,
        "strdata_end": loc.strdata_end,
        "entries": size,
        "sha256": sha256([list(p) for p in table]),
    }


def map_digest(mapping) -> dict:
    items = [[key, sorted(ids)] for key, ids in sorted(mapping.items())]
    return {"count": len(items), "sha256": sha256(items)}


def dump_type_map(buf, name):
    loc = TypeLocator(fresh(buf, name))
    try:
        loc._build_map()
    except Exception as e:
        return error(e)
    return map_digest(loc.type_maps)


def dump_member_map(buf, name, cls, attr):
    loc = cls(fresh(buf, name))
    try:
        loc._build_map()
    except Exception as e:
        return error(e)
    return {"class": map_digest(loc.clz_maps), "name": map_digest(getattr(loc, attr))}


class _WalkRecorder(InsnLocator):
    walk = "map"

    def _build_map_bydef(self):
        if not self.parsed:
            self.walk = "def"
        return super()._build_map_bydef()


def dump_insn_map(buf, name):
    loc = _WalkRecorder(fresh(buf, name))
    try:
        loc.parse()
    except Exception as e:
        return error(e)
    buckets = [[b, owner] for b, owner in sorted(loc.insn_maps.items())]
    bounds = [[m, off] for m, off in sorted(loc.method_bounds.items())]
    return {
        "walk": loc.walk,
        "buckets": len(buckets),
        "code_item_start": loc.code_item_start,
        "code_item_end": loc.code_item_end,
        "buckets_sha256": sha256(buckets),
        "method_bounds": len(bounds),
        "method_bounds_sha256": sha256(bounds),
    }


def sample_member(dex, cls, count):
    """(class descriptor, name) of member 0, as the reference script takes it,
    or None when the table is empty or member 0 does not resolve."""
    if count == 0:
        return None
    try:
        member = cls(dex, 0)
        return member.cls.fullname, member.name
    except Exception:
        return None


def query_list(buf, name):
    """The fixed per-DEX query list: (kind, find value) pairs, CLI-shaped."""
    queries = [("string", p) for p in STRING_PATTERNS]
    queries += [("type", p) for p in TYPE_PATTERNS]
    try:
        dex = fresh(buf, name)
    except Exception:
        return queries
    # The first and last string_ids entries as literal patterns, each when it resolves.
    count = dex.header.strings[1]
    for idx in ((0, count - 1) if count else ()):
        try:
            queries.append(("string", re.escape(dex.get_string(idx))))
        except Exception:
            pass
    # The reference script's shapes, with this DEX's method 0 and field 0.
    for kind, cls, count, wild, fuzzy in (
        ("method", DexMethod, dex.header.methods[1], "view", "AccessibilityServiceInfo"),
        ("field", DexField, dex.header.fields[1], "action", "Notification"),
    ):
        queries.append((kind, {"class": None, kind: wild}))
        sample = sample_member(dex, cls, count)
        if sample is not None:
            sample_cls, sample_name = sample
            queries.append((kind, {"class": [sample_cls, True], kind: None}))
            queries.append((kind, {"class": [sample_cls, True], kind: sample_name}))
        queries.append((kind, {"class": [fuzzy, False], kind: None}))
        if sample is not None:
            queries.append((kind, {"class": [fuzzy, False], kind: sample_name}))
    return queries


def encode_query(kind, value):
    if kind in ("string", "type"):
        return units(value)
    clz = value["class"]
    return {
        "class": None if clz is None else [units(clz[0]), clz[1]],
        "name": None if value[kind] is None else units(value[kind]),
    }


def run_query(buf, name, kind, value):
    """Mirror FindRefManager.find_ref and AscHandler.findrefs stage by stage."""
    record = {"kind": kind, "query": encode_query(kind, value)}
    if kind == "string" and value in PYTHON_ONLY_PATTERNS:
        record["expect_rust"] = "unsupported_syntax"
    try:
        dex = fresh(buf, name)
        mgr = FindRefManager(dex)
        if kind == "string":
            located = mgr._get_str_locator(True).locate(value)
        elif kind == "type":
            located = mgr._get_type_locator(True).locate(value)
        elif kind == "method":
            located = mgr._get_method_locator(True).locate(copy.deepcopy(value))
        else:
            located = mgr._get_field_locator(True).locate(copy.deepcopy(value))
        record["located"] = compact(sorted(located))
        if located:
            scanner = mgr._get_code_scanner()
            offsets = scanner._scan_code_item(kind, located, True)
            record["offsets"] = compact(offsets)
            record["marks"] = compact(list(scanner.mark_idx))
            record["mids"] = compact(mgr.insn_locator.locate(offsets))
    except Exception as e:
        record["error"] = str(e)
        return record
    # The lines from the real entry point, on its own DEX object.
    try:
        lines = AscHandler().findrefs(name, buf, kind, {kind: copy.deepcopy(value)})
        record["lines"] = compact([units(line) for line in lines])
    except Exception as e:
        record["lines"] = error(e)
    return record


def dump_dex_findrefs(buf, name) -> dict:
    try:
        fresh(buf, name)
    except Exception as e:
        return {"name": units(name), "dex_parse": error(e)}
    return {
        "name": units(name),
        "string_map": dump_string_map(buf, name),
        "type_map": dump_type_map(buf, name),
        "method_map": dump_member_map(buf, name, MethodLocator, "method_maps"),
        "field_map": dump_member_map(buf, name, FieldLocator, "field_maps"),
        "insn_map": dump_insn_map(buf, name),
        "queries": [run_query(buf, name, kind, value) for kind, value in query_list(buf, name)],
    }


def dump_apk_findrefs(apk_path: Path) -> dict:
    if not apk_path.exists():
        return {"error": f"APK file not found: {apk_path}"}
    if apk_path.stat().st_size < 22:
        return {"error": "EOCD not found"}
    try:
        mm = apk_handler._get_worker_apk_mm(str(apk_path))
        entries = sorted(apk_handler._parse_cd_dex_entries(mm), key=lambda e: e[2])
    except Exception as e:
        return {"error": str(e)}
    # One record per logical DEX, in entry order (the order findrefs prints).
    dex = []
    for entry in entries:
        try:
            data = apk_handler._inflate_dex(mm, entry)
        except Exception as e:
            dex.append({"name": units(entry[0]), "inflate": error(e)})
            continue
        for logical_name, logical_buf in iter_logical_dex_buffers(entry[0], data):
            dex.append(dump_dex_findrefs(logical_buf, logical_name))
    return {"dex": dex}


def main():
    parser = argparse.ArgumentParser(description="Dump Droid ASC findrefs stages as JSON.")
    parser.add_argument("apk", help="Path to APK file")
    args = parser.parse_args()
    json.dump(dump_apk_findrefs(Path(args.apk)), sys.stdout, indent=2, sort_keys=True)


if __name__ == "__main__":
    main()
