#!/usr/bin/env python3
"""Python Primitive Oracle for Droid ASC Conformance.

Dumps primitive-level internal data structures for APKs and DEX files as JSON.
Every integer is serialized as a number, byte strings as lowercase hex,
and decoded strings as UTF-16 code unit arrays.
"""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import sys

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from droidasc.asc_client import apk_handler
from droidasc.asc_client.dex_container import (
    dex041_logical_offsets,
    is_dex041_container,
    iter_logical_dex_buffers,
    normalize_dex041_logical,
)
from droidasc.asc_core.models import dvm_opcode
from droidasc.asc_core.utils.leb128 import read_uleb128_fast
from droidasc.asc_core.utils.mutf8 import decode_mutf8, encode_mutf8
from droidasc.asc_core.utils.tinydex import DEX, DEXHeader, Type


def to_utf16_units(s: str) -> list[int]:
    """Convert a Python string (possibly containing surrogates) to UTF-16 code units."""
    raw_le = s.encode("utf-16-le", "surrogatepass")
    return list(struct.unpack(f"<{len(raw_le) >> 1}H", raw_le))


def dump_opcodes() -> dict:
    """Dump DVM opcode table."""
    result = {}
    vflag_members = list(dvm_opcode.VerifyFlag.__members__.keys())
    for op in range(256):
        if op not in dvm_opcode.opcodes:
            result[f"0x{op:02x}"] = None
            continue
        info = dvm_opcode.opcodes[op]
        flag_names = []
        val = info.vflag.value if hasattr(info.vflag, "value") else int(info.vflag)
        for member_name in vflag_members:
            flag_val = dvm_opcode.VerifyFlag[member_name].value
            if (val & flag_val) == flag_val:
                flag_names.append(member_name)

        fmt_name = info.fmt.name if hasattr(info.fmt, "name") else str(info.fmt)
        idx_name = info.idx.name if hasattr(info.idx, "name") else str(info.idx)
        result[f"0x{op:02x}"] = {
            "name": info.name,
            "oplen": info.oplen,
            "fmt": fmt_name,
            "idx": idx_name,
            "vflag": flag_names,
        }
    return result


def dump_dex_primitives(dex_buf: bytes, dex_name: str, query_list: list[str]) -> dict:
    """Dump primitive structures of a single logical DEX buffer."""
    result = {}

    # 1. Header
    try:
        header = DEXHeader(dex_buf)
        result["header"] = {
            "strings": list(header.strings),
            "types": list(header.types),
            "prototypes": list(header.prototypes),
            "fields": list(header.fields),
            "methods": list(header.methods),
            "classes": list(header.classes),
            "mapoff": header.mapoff,
        }
    except Exception as e:
        result["header"] = {"error": str(e)}
        return result

    # 2. DEX object for high-level structures
    try:
        dex = DEX.parse(memoryview(dex_buf), dex_name)
    except Exception as e:
        result["dex_parse"] = {"error": str(e)}
        return result

    # 3. Strings
    strings_dump = []
    str_off_table = header.strings[0]
    str_count = header.strings[1]
    str_err = None
    for idx in range(str_count):
        try:
            if str_off_table + idx * 4 + 4 > len(dex_buf):
                raise ValueError("bad string_ids range")
            str_data_off = struct.unpack_from("<I", dex_buf, str_off_table + idx * 4)[0]
            if str_data_off >= len(dex_buf):
                raise ValueError("bad string_data offset")
            u16_len, _ = read_uleb128_fast(dex_buf, str_data_off)
            raw_bytes = dex.get_string_bytes(idx)
            decoded = dex.get_string(idx)
            strings_dump.append({
                "idx": idx,
                "data_off": str_data_off,
                "utf16_len": u16_len,
                "raw": raw_bytes.hex(),
                "units": to_utf16_units(decoded),
            })
        except Exception as e:
            str_err = str(e)
            break
    if str_err is not None:
        result["strings"] = {"error": str_err, "partial": strings_dump}
    else:
        result["strings"] = strings_dump

    # 4. Types
    types_dump = []
    type_count = header.types[1]
    type_off_table = header.types[0]
    type_err = None
    for idx in range(type_count):
        try:
            if type_off_table + idx * 4 + 4 > len(dex_buf):
                raise ValueError("bad type_ids range")
            str_idx = struct.unpack_from("<I", dex_buf, type_off_table + idx * 4)[0]
            t = dex.get_type(idx)
            kind_str = {
                Type.TYPES.PRIMITIVE: "primitive",
                Type.TYPES.CLASS: "class",
                Type.TYPES.ARRAY: "array",
            }.get(t.type, "unknown")
            types_dump.append({
                "idx": idx,
                "str_idx": str_idx,
                "descriptor": to_utf16_units(t.descriptor),
                "dim": t.dim,
                "kind": kind_str,
                "value": t.value if kind_str == "primitive" else (to_utf16_units(t.value) if isinstance(t.value, str) else None),
            })
        except Exception as e:
            type_err = str(e)
            break
    if type_err is not None:
        result["types"] = {"error": type_err, "partial": types_dump}
    else:
        result["types"] = types_dump

    # 5. Prototypes
    protos_dump = []
    proto_count = header.prototypes[1]
    proto_off_table = header.prototypes[0]
    proto_err = None
    for idx in range(proto_count):
        try:
            if proto_off_table + idx * 12 + 12 > len(dex_buf):
                raise ValueError("bad proto_ids range")
            p = dex.get_prototype(idx)
            param_idxs = []
            if p.parameters_off != 0:
                param_size = struct.unpack_from("<I", dex_buf, p.parameters_off)[0]
                p_off = p.parameters_off + 4
                for _ in range(param_size):
                    param_idxs.append(struct.unpack_from("<H", dex_buf, p_off)[0])
                    p_off += 2
            protos_dump.append({
                "idx": idx,
                "shorty_idx": p.shorty_idx,
                "return_type_idx": p.return_type_idx,
                "parameters_off": p.parameters_off,
                "param_type_idxs": param_idxs,
            })
        except Exception as e:
            proto_err = str(e)
            break
    if proto_err is not None:
        result["protos"] = {"error": proto_err, "partial": protos_dump}
    else:
        result["protos"] = protos_dump

    # 6. Fields
    fields_dump = []
    field_count = header.fields[1]
    field_off_table = header.fields[0]
    field_err = None
    for idx in range(field_count):
        try:
            if field_off_table + idx * 8 + 8 > len(dex_buf):
                raise ValueError("bad field_ids range")
            f = dex.get_field(idx)
            fields_dump.append({
                "idx": idx,
                "class_idx": f.class_idx,
                "type_idx": f.type_idx,
                "name_idx": f.name_idx,
            })
        except Exception as e:
            field_err = str(e)
            break
    if field_err is not None:
        result["fields"] = {"error": field_err, "partial": fields_dump}
    else:
        result["fields"] = fields_dump

    # 7. Methods
    methods_dump = []
    method_count = header.methods[1]
    method_off_table = header.methods[0]
    method_err = None
    for idx in range(method_count):
        try:
            if method_off_table + idx * 8 + 8 > len(dex_buf):
                raise ValueError("bad method_ids range")
            m = dex.get_method(idx)
            methods_dump.append({
                "idx": idx,
                "class_idx": m.class_idx,
                "proto_idx": m.proto_idx,
                "name_idx": m.name_idx,
            })
        except Exception as e:
            method_err = str(e)
            break
    if method_err is not None:
        result["methods"] = {"error": method_err, "partial": methods_dump}
    else:
        result["methods"] = methods_dump

    # 8. Classes & Class Data
    classes_dump = []
    class_count = header.classes[1]
    class_off_table = header.classes[0]
    class_err = None
    for idx in range(class_count):
        try:
            if class_off_table + idx * 32 + 32 > len(dex_buf):
                raise ValueError("bad class_defs range")
            c = dex.classes[idx]
            c._parse_class_data()
            static_fields = [[f.index, f.access_flags] for f in c.fields if f.is_static]
            instance_fields = [[f.index, f.access_flags] for f in c.fields if not f.is_static]
            direct_methods = [[m.index, m.access_flags, m.code_offset] for m in c.methods if m.is_direct]
            virtual_methods = [[m.index, m.access_flags, m.code_offset] for m in c.methods if m.is_virtual]
            classes_dump.append({
                "class_idx": c.class_idx,
                "class_def_off": c._class_def_off,
                "class_data_off": c.class_data_off,
                "fullname": to_utf16_units(c.fullname),
                "static_fields": static_fields,
                "instance_fields": instance_fields,
                "direct_methods": direct_methods,
                "virtual_methods": virtual_methods,
            })
        except Exception as e:
            class_err = str(e)
            break
    if class_err is not None:
        result["classes"] = {"error": class_err, "partial": classes_dump}
    else:
        result["classes"] = classes_dump

    # 9. Code Items
    code_items_dump = {}
    code_err = None
    for idx in range(class_count):
        try:
            if class_off_table + idx * 32 + 32 > len(dex_buf):
                raise ValueError("bad class_defs range")
            c = dex.classes[idx]
            c._parse_class_data()
            for m in c.methods:
                if m.code_offset != 0 and str(m.code_offset) not in code_items_dump:
                    off = m.code_offset
                    registers_size, ins_size, outs_size, tries_size, debug_info_off, insns_size = struct.unpack_from(
                        "<HHHHII", dex_buf, off
                    )
                    insns_bytes = dex_buf[off + 16 : off + 16 + insns_size * 2]
                    code_items_dump[str(off)] = {
                        "method_idx": m.index,
                        "code_off": off,
                        "registers_size": registers_size,
                        "ins_size": ins_size,
                        "outs_size": outs_size,
                        "tries_size": tries_size,
                        "debug_info_off": debug_info_off,
                        "insns_size": insns_size,
                        "insns_sha256": hashlib.sha256(insns_bytes).hexdigest(),
                    }
        except Exception as e:
            code_err = str(e)
            break
    if code_err is not None:
        result["code_items"] = {"error": code_err, "partial": code_items_dump}
    else:
        result["code_items"] = code_items_dump

    # 10. get_class on query list
    get_class_dump = []
    for q in query_list:
        try:
            if header.strings[0] + header.strings[1] * 4 > len(dex_buf):
                raise ValueError("bad string_ids range")
            if header.types[0] + header.types[1] * 4 > len(dex_buf):
                raise ValueError("bad type_ids range")
            if class_off_table + class_count * 32 > len(dex_buf):
                raise ValueError("bad class_defs range")
            cls_obj = dex.get_class(q)
            get_class_dump.append({
                "name": q,
                "found": cls_obj is not None,
                "class_idx": cls_obj.class_idx if cls_obj is not None else None,
            })
        except Exception as e:
            get_class_dump.append({"name": q, "error": str(e)})
    result["get_class"] = get_class_dump

    return result


def dump_apk_primitives(apk_path: Path, extra_queries: list[str] = None) -> dict:
    """Dump all primitive sections for an APK file."""
    result = {}

    if not apk_path.exists():
        return {"error": f"APK file not found: {apk_path}"}
    if apk_path.stat().st_size < 22:
        return {"error": "EOCD not found"}

    try:
        mm = apk_handler._get_worker_apk_mm(str(apk_path))
    except Exception as e:
        return {"error": str(e)}

    # 1. EOCD & Central Directory entries
    try:
        eocd_idx = apk_handler._find_eocd(mm)
        if eocd_idx < 0:
            raise ValueError("EOCD not found")
        if eocd_idx + 22 > len(mm):
            raise ValueError("bad EOCD header")
        cd_size = struct.unpack_from("<I", mm, eocd_idx + 12)[0]
        cd_off = struct.unpack_from("<I", mm, eocd_idx + 16)[0]
        if cd_off > len(mm) or cd_off + cd_size > len(mm):
            raise ValueError("bad central directory range")

        # Check fast path
        fast_pos = mm.find(b"classes", cd_off, cd_off + cd_size)
        fast_path = fast_pos >= 0

        raw_entries = apk_handler._parse_cd_dex_entries(mm)
        sorted_entries = sorted(raw_entries, key=lambda e: e[2])  # comp_size stable sort

        entries_list = []
        for e in sorted_entries:
            entries_list.append({
                "name": e[0],
                "uncomp_size": e[1],
                "comp_size": e[2],
                "local_header_off": e[3],
                "method": e[4],
            })
        result["apk.entries"] = {
            "eocd_off": eocd_idx,
            "cd_off": cd_off,
            "cd_size": cd_size,
            "fast_path": fast_path,
            "entries": entries_list,
        }
    except Exception as e:
        result["apk.entries"] = {"error": str(e)}
        return result

    # 2. Inflate entries
    inflate_dump = {}
    inflated_dex_data = {}
    for e in sorted_entries:
        try:
            data = apk_handler._inflate_dex(mm, e)
            inflated_dex_data[e[0]] = data
            inflate_dump[e[0]] = {
                "sha256": hashlib.sha256(data).hexdigest(),
                "size": len(data),
            }
        except Exception as e_inf:
            inflate_dump[e[0]] = {"error": str(e_inf)}
    result["apk.inflate"] = inflate_dump

    # Determine all class names across all DEXes to form query list
    class_names_found = []
    for ename, data in inflated_dex_data.items():
        if len(data) >= 0x70 and data[:3] == b"dex":
            try:
                d = DEX.parse(memoryview(data), ename)
                for c in range(d.header.classes[1]):
                    class_names_found.append(d.classes[c].fullname)
            except Exception:
                pass

    probe_names = [
        "Ldoes/not/Exist;",
        "Lcom/missing/TargetClass;",
        "Lnonexistent/Cls;",
    ]
    query_list = sorted(set(class_names_found + probe_names + (extra_queries or [])))

    # 3. apk.defines_class
    defines_dump = {}
    for ename, data in inflated_dex_data.items():
        entry_defines = []
        for q in query_list:
            q_bytes = encode_mutf8(q)
            try:
                t_idx = apk_handler._find_type_idx(data, q_bytes)
                is_def = apk_handler._dex_defines_class(data, q_bytes) if t_idx >= 0 else False
                entry_defines.append({
                    "name": q,
                    "type_idx": t_idx,
                    "defined": is_def,
                })
            except Exception as e:
                entry_defines.append({"name": q, "error": str(e)})
        defines_dump[ename] = entry_defines
    result["apk.defines_class"] = defines_dump

    # 4. Containers and logical DEX primitives
    dex_sections = {}
    for ename, data in inflated_dex_data.items():
        is_041 = is_dex041_container(data)
        log_offsets = dex041_logical_offsets(data)

        for logical_name, logical_buf in iter_logical_dex_buffers(ename, data):
            dex_entry_dump = {
                "container": {
                    "is_041": is_041,
                    "logical_offsets": log_offsets,
                    "logical_name": logical_name,
                    "normalized_sha256": hashlib.sha256(logical_buf).hexdigest(),
                }
            }
            primitives = dump_dex_primitives(logical_buf, logical_name, query_list)
            dex_entry_dump.update(primitives)
            dex_sections[logical_name] = dex_entry_dump

    result["dex"] = dex_sections
    result["opcodes"] = dump_opcodes()
    return result


def main():
    parser = argparse.ArgumentParser(description="Dump Droid ASC primitive data structures as JSON.")
    parser.add_argument("apk", help="Path to APK file")
    parser.add_argument("--queries", help="Path to queries file")
    parser.add_argument("--output-dir", help="Directory to save per-DEX and APK JSON files")
    args = parser.parse_args()

    extra_queries = []
    if args.queries:
        with open(args.queries, "r", encoding="utf-8") as f:
            extra_queries = [line.strip() for line in f if line.strip()]

    dump = dump_apk_primitives(Path(args.apk), extra_queries)

    if args.output_dir:
        out_dir = Path(args.output_dir)
        out_dir.mkdir(parents=True, exist_ok=True)
        # Write apk.json
        apk_json = {
            "apk.entries": dump.get("apk.entries"),
            "apk.inflate": dump.get("apk.inflate"),
            "apk.defines_class": dump.get("apk.defines_class"),
            "opcodes": dump.get("opcodes"),
        }
        with open(out_dir / "apk.json", "w", encoding="utf-8") as f:
            json.dump(apk_json, f, indent=2, sort_keys=True)

        # Write each logical DEX json
        for dex_name, dex_data in dump.get("dex", {}).items():
            safe_name = dex_name.replace("/", "_")
            with open(out_dir / f"{safe_name}.json", "w", encoding="utf-8") as f:
                json.dump(dex_data, f, indent=2, sort_keys=True)

    json.dump(dump, sys.stdout, indent=2, sort_keys=True)


if __name__ == "__main__":
    main()
