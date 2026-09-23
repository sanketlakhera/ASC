use asc_core::dex::{
    Dex, TypeKind, dex_defines_class_raw, dex041_logical_offsets, find_type_idx_raw,
    is_dex041_container, iter_logical_dex_buffers,
};
use asc_core::inflate::inflate_entry;
use asc_core::mutf8::encode_mutf8;
use asc_core::opcode::OPCODES;
use asc_core::zip::{find_eocd, parse_cd_dex_entries};
use clap::{Parser, Subcommand};
use memmap2::Mmap;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File};
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(name = "asc", version, about = "Droid ASC command-line tool")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    #[command(name = "dump-primitives", hide = true)]
    DumpPrimitives {
        apk: PathBuf,
        #[arg(long)]
        queries: Option<PathBuf>,
        #[arg(long)]
        output_dir: Option<PathBuf>,
    },
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    let hash = hasher.finalize();
    let mut s = String::with_capacity(64);
    for b in hash {
        use std::fmt::Write as _;
        write!(&mut s, "{:02x}", b).unwrap();
    }
    s
}

fn dump_opcodes() -> BTreeMap<String, Value> {
    let mut map = BTreeMap::new();
    for (op, info_opt) in OPCODES.iter().enumerate() {
        let key = format!("0x{:02x}", op);
        if let Some(info) = info_opt {
            let vflags = info.verify.flag_names();
            map.insert(
                key,
                json!({
                    "name": info.name,
                    "oplen": info.len,
                    "fmt": info.fmt.as_str(),
                    "idx": info.idx.as_str(),
                    "vflag": vflags,
                }),
            );
        } else {
            map.insert(key, Value::Null);
        }
    }
    map
}

fn dump_dex_primitives(dex_buf: &[u8], _dex_name: &str, query_list: &[String]) -> Value {
    let mut result = json!({});

    // 1. Header
    let dex = match Dex::new(dex_buf) {
        Ok(d) => d,
        Err(e) => {
            result["header"] = json!({ "error": e.to_string() });
            return result;
        }
    };

    result["header"] = json!({
        "strings": [dex.header.strings.0, dex.header.strings.1],
        "types": [dex.header.types.0, dex.header.types.1],
        "prototypes": [dex.header.prototypes.0, dex.header.prototypes.1],
        "fields": [dex.header.fields.0, dex.header.fields.1],
        "methods": [dex.header.methods.0, dex.header.methods.1],
        "classes": [dex.header.classes.0, dex.header.classes.1],
        "mapoff": dex.header.map_off,
    });

    // 2. Strings
    let mut strings_dump = Vec::new();
    let str_count = dex.header.strings.1;
    let mut str_err = None;
    for idx in 0..str_count {
        match (
            dex.get_string_data_off(idx),
            dex.get_string_bytes(idx),
            dex.get_string(idx),
        ) {
            (Ok(str_data_off), Ok(raw_bytes), Ok(decoded)) => {
                let (utf16_len, _) =
                    asc_core::leb128::read_uleb128(dex_buf, str_data_off).unwrap_or((0, 0));
                let mut raw_hex = String::with_capacity(raw_bytes.len() * 2);
                for b in raw_bytes {
                    use std::fmt::Write as _;
                    write!(&mut raw_hex, "{:02x}", b).unwrap();
                }
                strings_dump.push(json!({
                    "idx": idx,
                    "data_off": str_data_off,
                    "utf16_len": utf16_len,
                    "raw": raw_hex,
                    "units": decoded.as_slice(),
                }));
            }
            (Err(e), _, _) | (_, Err(e), _) | (_, _, Err(e)) => {
                str_err = Some(e.to_string());
                break;
            }
        }
    }
    if let Some(err) = str_err {
        result["strings"] = json!({ "error": err, "partial": strings_dump });
    } else {
        result["strings"] = json!(strings_dump);
    }

    // 3. Types
    let mut types_dump = Vec::new();
    let type_count = dex.header.types.1;
    let mut type_err = None;
    for idx in 0..type_count {
        match dex.get_type(idx) {
            Ok((str_idx, t_info)) => {
                let (kind_str, val_json) = match t_info.kind {
                    TypeKind::Primitive(v) => ("primitive", json!(v)),
                    TypeKind::Class => ("class", json!(t_info.descriptor.as_slice())),
                    TypeKind::Array => ("array", Value::Null),
                };
                types_dump.push(json!({
                    "idx": idx,
                    "str_idx": str_idx,
                    "descriptor": t_info.descriptor.as_slice(),
                    "dim": t_info.dim,
                    "kind": kind_str,
                    "value": val_json,
                }));
            }
            Err(e) => {
                type_err = Some(e.to_string());
                break;
            }
        }
    }
    if let Some(err) = type_err {
        result["types"] = json!({ "error": err, "partial": types_dump });
    } else {
        result["types"] = json!(types_dump);
    }

    // 4. Prototypes
    let mut protos_dump = Vec::new();
    let proto_count = dex.header.prototypes.1;
    let mut proto_err = None;
    for idx in 0..proto_count {
        match dex.get_prototype(idx) {
            Ok(p) => {
                protos_dump.push(json!({
                    "idx": idx,
                    "shorty_idx": p.shorty_idx,
                    "return_type_idx": p.return_type_idx,
                    "parameters_off": p.parameters_off,
                    "param_type_idxs": p.param_type_idxs,
                }));
            }
            Err(e) => {
                proto_err = Some(e.to_string());
                break;
            }
        }
    }
    if let Some(err) = proto_err {
        result["protos"] = json!({ "error": err, "partial": protos_dump });
    } else {
        result["protos"] = json!(protos_dump);
    }

    // 5. Fields
    let mut fields_dump = Vec::new();
    let field_count = dex.header.fields.1;
    let mut field_err = None;
    for idx in 0..field_count {
        match dex.get_field(idx) {
            Ok(f) => {
                fields_dump.push(json!({
                    "idx": idx,
                    "class_idx": f.class_idx,
                    "type_idx": f.type_idx,
                    "name_idx": f.name_idx,
                }));
            }
            Err(e) => {
                field_err = Some(e.to_string());
                break;
            }
        }
    }
    if let Some(err) = field_err {
        result["fields"] = json!({ "error": err, "partial": fields_dump });
    } else {
        result["fields"] = json!(fields_dump);
    }

    // 6. Methods
    let mut methods_dump = Vec::new();
    let method_count = dex.header.methods.1;
    let mut method_err = None;
    for idx in 0..method_count {
        match dex.get_method(idx) {
            Ok(m) => {
                methods_dump.push(json!({
                    "idx": idx,
                    "class_idx": m.class_idx,
                    "proto_idx": m.proto_idx,
                    "name_idx": m.name_idx,
                }));
            }
            Err(e) => {
                method_err = Some(e.to_string());
                break;
            }
        }
    }
    if let Some(err) = method_err {
        result["methods"] = json!({ "error": err, "partial": methods_dump });
    } else {
        result["methods"] = json!(methods_dump);
    }

    // 7. Classes & Class Data
    let mut classes_dump = Vec::new();
    let class_count = dex.header.classes.1;
    let mut class_err = None;
    let mut parsed_classes = Vec::new();
    for idx in 0..class_count {
        match dex.get_class(idx) {
            Ok(c) => {
                classes_dump.push(json!({
                    "class_idx": c.class_idx,
                    "class_def_off": c.class_def_off,
                    "class_data_off": c.class_data_off,
                    "fullname": c.fullname.as_slice(),
                    "static_fields": c.static_fields,
                    "instance_fields": c.instance_fields,
                    "direct_methods": c.direct_methods,
                    "virtual_methods": c.virtual_methods,
                }));
                parsed_classes.push(c);
            }
            Err(e) => {
                class_err = Some(e.to_string());
                break;
            }
        }
    }
    if let Some(err) = class_err {
        result["classes"] = json!({ "error": err, "partial": classes_dump });
    } else {
        result["classes"] = json!(classes_dump);
    }

    // 8. Code Items
    let mut code_items_dump = BTreeMap::new();
    let mut code_err = None;
    for idx in 0..class_count {
        let c = match dex.get_class(idx) {
            Ok(c) => c,
            Err(e) => {
                code_err = Some(e.to_string());
                break;
            }
        };
        for m in &c.all_methods {
            if m.code_off != 0 && !code_items_dump.contains_key(&m.code_off.to_string()) {
                let off = m.code_off as usize;
                match dex.get_code_item(off) {
                    Ok(item) => {
                        code_items_dump.insert(
                            off.to_string(),
                            json!({
                                "method_idx": m.index,
                                "code_off": off,
                                "registers_size": item.registers_size,
                                "ins_size": item.ins_size,
                                "outs_size": item.outs_size,
                                "tries_size": item.tries_size,
                                "debug_info_off": item.debug_info_off,
                                "insns_size": item.insns_size,
                                "insns_sha256": sha256_hex(item.insns_bytes),
                            }),
                        );
                    }
                    Err(e) => {
                        code_err = Some(e.to_string());
                        break;
                    }
                }
            }
        }
        if code_err.is_some() {
            break;
        }
    }
    if let Some(err) = code_err {
        result["code_items"] = json!({ "error": err, "partial": code_items_dump });
    } else {
        result["code_items"] = json!(code_items_dump);
    }

    // 9. get_class queries
    let mut get_class_dump = Vec::new();
    for q in query_list {
        match dex.find_class(q) {
            Ok(found_opt) => {
                let class_idx =
                    found_opt.and_then(|idx| parsed_classes.get(idx).map(|c| c.class_idx));
                get_class_dump.push(json!({
                    "name": q,
                    "found": found_opt.is_some(),
                    "class_idx": class_idx,
                }));
            }
            Err(e) => {
                get_class_dump.push(json!({
                    "name": q,
                    "error": e.to_string(),
                }));
            }
        }
    }
    result["get_class"] = json!(get_class_dump);

    result
}

fn dump_apk_primitives(apk_bytes: &[u8], extra_queries: &[String]) -> Value {
    let mut result = json!({});

    // 1. EOCD & Central Directory
    let eocd = match find_eocd(apk_bytes) {
        Ok(e) => e,
        Err(e) => return json!({ "apk.entries": { "error": e.to_string() } }),
    };

    let cd_off = eocd.cd_off;
    let cd_size = eocd.cd_size;
    let fast_path = apk_bytes
        .get(cd_off..cd_off + cd_size)
        .is_some_and(|s| s.windows(7).any(|w| w == b"classes"));

    let raw_entries = match parse_cd_dex_entries(apk_bytes) {
        Ok(e) => e,
        Err(e) => {
            return json!({ "apk.entries": { "error": e.to_string() } });
        }
    };

    let mut sorted_entries = raw_entries.clone();
    sorted_entries.sort_by_key(|e| e.comp_size);

    let entries_list: Vec<Value> = sorted_entries
        .iter()
        .map(|e| {
            json!({
                "name": e.name,
                "uncomp_size": e.uncomp_size,
                "comp_size": e.comp_size,
                "local_header_off": e.local_header_off,
                "method": e.method,
            })
        })
        .collect();

    result["apk.entries"] = json!({
        "eocd_off": eocd.offset,
        "cd_off": cd_off,
        "cd_size": cd_size,
        "fast_path": fast_path,
        "entries": entries_list,
    });

    // 2. Inflate entries
    let mut inflate_dump = BTreeMap::new();
    let mut inflated_dex_data: Vec<(String, Vec<u8>)> = Vec::new();

    for e in &sorted_entries {
        match inflate_entry(apk_bytes, e, None) {
            Ok(Some(raw)) => {
                inflate_dump.insert(
                    e.name.clone(),
                    json!({
                        "sha256": sha256_hex(&raw),
                        "size": raw.len(),
                    }),
                );
                inflated_dex_data.push((e.name.clone(), raw));
            }
            Ok(None) => {}
            Err(err) => {
                inflate_dump.insert(e.name.clone(), json!({ "error": err.to_string() }));
            }
        }
    }
    result["apk.inflate"] = json!(inflate_dump);

    // Collect class names to build query list
    let mut class_names_set = BTreeSet::new();
    for (_ename, data) in &inflated_dex_data {
        if data.len() < 0x70 || data.get(..3) != Some(b"dex") {
            continue;
        }
        let Ok(dex) = Dex::new(data) else {
            continue;
        };
        for idx in 0..dex.header.classes.1 {
            if let Ok(cls) = dex.get_class(idx) {
                class_names_set.insert(cls.fullname.to_string_lossy());
            }
        }
    }

    let probe_names = [
        "Ldoes/not/Exist;",
        "Lcom/missing/TargetClass;",
        "Lnonexistent/Cls;",
    ];
    for p in probe_names {
        class_names_set.insert(p.to_string());
    }
    for eq in extra_queries {
        class_names_set.insert(eq.clone());
    }

    let query_list: Vec<String> = class_names_set.into_iter().collect();

    // 3. apk.defines_class
    let mut defines_dump = BTreeMap::new();
    for (ename, data) in &inflated_dex_data {
        let mut entry_defines = Vec::new();

        for q in &query_list {
            let q_units: Vec<u16> = q.encode_utf16().collect();
            let q_bytes = encode_mutf8(&q_units);

            match find_type_idx_raw(data, &q_bytes) {
                Ok(Some(t_idx)) => {
                    let defined = dex_defines_class_raw(data, &q_bytes).unwrap_or(false);
                    entry_defines.push(json!({
                        "name": q,
                        "type_idx": t_idx,
                        "defined": defined,
                    }));
                }
                Ok(None) => {
                    entry_defines.push(json!({
                        "name": q,
                        "type_idx": -1,
                        "defined": false,
                    }));
                }
                Err(e) => {
                    entry_defines.push(json!({
                        "name": q,
                        "error": e.to_string(),
                    }));
                }
            }
        }
        defines_dump.insert(ename.clone(), entry_defines);
    }
    result["apk.defines_class"] = json!(defines_dump);

    // 4. Containers and logical DEX primitives
    let mut dex_sections = BTreeMap::new();
    for (ename, data) in &inflated_dex_data {
        let is_041 = is_dex041_container(data);
        let log_offsets = dex041_logical_offsets(data);

        for (logical_name, logical_buf) in iter_logical_dex_buffers(ename, data) {
            let mut dex_entry_dump = json!({
                "container": {
                    "is_041": is_041,
                    "logical_offsets": log_offsets,
                    "logical_name": logical_name,
                    "normalized_sha256": sha256_hex(&logical_buf),
                }
            });

            let primitives = dump_dex_primitives(&logical_buf, &logical_name, &query_list);
            if let (Some(obj), Some(prim_obj)) =
                (dex_entry_dump.as_object_mut(), primitives.as_object())
            {
                for (k, v) in prim_obj {
                    obj.insert(k.clone(), v.clone());
                }
            }
            dex_sections.insert(logical_name, dex_entry_dump);
        }
    }
    result["dex"] = json!(dex_sections);

    // 5. Global opcodes table
    result["opcodes"] = json!(dump_opcodes());

    result
}

fn main() {
    let cli = Cli::parse();
    match cli.command {
        Commands::DumpPrimitives {
            apk,
            queries,
            output_dir,
        } => {
            if !apk.exists() {
                let err_json = json!({
                    "error": format!("APK file not found: {}", apk.display())
                });
                println!("{}", serde_json::to_string_pretty(&err_json).unwrap());
                return;
            }

            let file_size = match fs::metadata(&apk) {
                Ok(m) => m.len(),
                Err(e) => {
                    let err_json = json!({ "error": e.to_string() });
                    println!("{}", serde_json::to_string_pretty(&err_json).unwrap());
                    return;
                }
            };

            if file_size < 22 {
                let err_json = json!({ "error": "EOCD not found" });
                println!("{}", serde_json::to_string_pretty(&err_json).unwrap());
                return;
            }

            let file = match File::open(&apk) {
                Ok(f) => f,
                Err(e) => {
                    let err_json = json!({ "error": e.to_string() });
                    println!("{}", serde_json::to_string_pretty(&err_json).unwrap());
                    return;
                }
            };

            let mmap = match unsafe { Mmap::map(&file) } {
                Ok(m) => m,
                Err(e) => {
                    let err_json = json!({ "error": e.to_string() });
                    println!("{}", serde_json::to_string_pretty(&err_json).unwrap());
                    return;
                }
            };

            let mut extra_queries = Vec::new();
            if let Some(content) = queries.and_then(|p| fs::read_to_string(p).ok()) {
                for line in content.lines() {
                    let trimmed = line.trim();
                    if !trimmed.is_empty() {
                        extra_queries.push(trimmed.to_string());
                    }
                }
            }

            let dump = dump_apk_primitives(&mmap, &extra_queries);

            if let Some(out_dir) = output_dir {
                let _ = fs::create_dir_all(&out_dir);
                let apk_json = json!({
                    "apk.entries": dump.get("apk.entries"),
                    "apk.inflate": dump.get("apk.inflate"),
                    "apk.defines_class": dump.get("apk.defines_class"),
                    "opcodes": dump.get("opcodes"),
                });
                if let Ok(mut f) = File::create(out_dir.join("apk.json")) {
                    let _ = serde_json::to_writer_pretty(&mut f, &apk_json);
                }
                if let Some(dex_map) = dump.get("dex").and_then(|d| d.as_object()) {
                    for (dex_name, dex_data) in dex_map {
                        let safe_name = dex_name.replace('/', "_");
                        if let Ok(mut f) = File::create(out_dir.join(format!("{safe_name}.json"))) {
                            let _ = serde_json::to_writer_pretty(&mut f, dex_data);
                        }
                    }
                }
            }

            println!("{}", serde_json::to_string_pretty(&dump).unwrap());
        }
    }
}
