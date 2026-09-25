//! `asc dump-findrefs APK`: the findrefs stages as JSON, record for record
//! the output of `rust/conformance/dump_findrefs.py`.

use asc_core::dex::{Dex, iter_logical_dex_buffers};
use asc_core::findrefs::insn::{InsnLocator, Owner, Walk};
use asc_core::findrefs::member::{MemberKind, MemberLocator, MemberQuery};
use asc_core::findrefs::string::StringLocator;
use asc_core::findrefs::types::TypeLocator;
use asc_core::findrefs::{self, FindRefs, Query};
use asc_core::inflate::inflate_entry;
use asc_core::zip::parse_cd_dex_entries;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

const COMPACT_LIMIT: usize = 64;
const COMPACT_HEAD: usize = 16;
const STRING_PATTERNS: &[&str] = &[
    "token",
    "create",
    "",
    ".",
    "token.",
    "^L",
    "(?i)VIEW",
    "a{",
    "(?<=t)oken",
];
const TYPE_PATTERNS: &[&str] = &["Lexample/Test;", "View"];

fn units(s: &str) -> Vec<u16> {
    s.encode_utf16().collect()
}

/// SHA-256 of the canonical JSON text (no spaces), as `json.dumps(v,
/// separators=(",", ":"))` writes it.
fn sha256(v: &Value) -> String {
    let text = serde_json::to_string(v).unwrap_or_default();
    Sha256::digest(text.as_bytes())
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

fn compact(values: Vec<Value>) -> Value {
    if values.len() <= COMPACT_LIMIT {
        return Value::Array(values);
    }
    let head: Vec<Value> = values.iter().take(COMPACT_HEAD).cloned().collect();
    let count = values.len();
    let digest = sha256(&Value::Array(values));
    json!({ "count": count, "sha256": digest, "head": head })
}

fn error(e: impl ToString) -> Value {
    json!({ "error": e.to_string() })
}

fn dump_string_map(buf: &[u8]) -> Value {
    let Ok(dex) = Dex::new(buf) else {
        return Value::Null;
    };
    match StringLocator::build(&dex) {
        Err(e) => error(e),
        Ok(loc) => {
            let (start, end) = loc.region();
            let table: Vec<Value> = StringLocator::table(&dex)
                .into_iter()
                .map(|(o, i)| json!([o, i]))
                .collect();
            json!({
                "strdata_start": start,
                "strdata_end": end,
                "entries": loc.entries(),
                "sha256": sha256(&Value::Array(table)),
            })
        }
    }
}

fn map_digest(entries: Vec<(u32, &[u32])>) -> Value {
    let items: Vec<Value> = entries
        .into_iter()
        .map(|(k, ids)| json!([k, ids]))
        .collect();
    json!({ "count": items.len(), "sha256": sha256(&Value::Array(items)) })
}

fn dump_type_map(buf: &[u8]) -> Value {
    let Ok(dex) = Dex::new(buf) else {
        return Value::Null;
    };
    match TypeLocator::build(&dex) {
        Err(e) => error(e),
        Ok(loc) => map_digest(loc.entries()),
    }
}

fn dump_member_map(buf: &[u8], kind: MemberKind) -> Value {
    let Ok(dex) = Dex::new(buf) else {
        return Value::Null;
    };
    match MemberLocator::build(&dex, kind) {
        Err(e) => error(e),
        Ok(loc) => {
            json!({ "class": map_digest(loc.class_entries()), "name": map_digest(loc.name_entries()) })
        }
    }
}

fn owner_json(owner: &Owner) -> Value {
    match owner {
        Owner::One(m) => json!(m),
        Owner::Many(ms) => json!(ms),
    }
}

fn dump_insn_map(buf: &[u8]) -> Value {
    let Ok(dex) = Dex::new(buf) else {
        return Value::Null;
    };
    match InsnLocator::parse(&dex) {
        Err(e) => error(e),
        Ok(loc) => {
            let buckets: Vec<Value> = loc
                .bucket_entries()
                .map(|(b, o)| json!([b, owner_json(&o)]))
                .collect();
            let bounds: Vec<Value> = loc
                .bounds()
                .into_iter()
                .map(|(m, o)| json!([m, o]))
                .collect();
            let (start, end) = loc.code_range();
            json!({
                "walk": if loc.walk == Walk::Map { "map" } else { "def" },
                "buckets": buckets.len(),
                "code_item_start": start,
                "code_item_end": end,
                "buckets_sha256": sha256(&Value::Array(buckets)),
                "method_bounds": bounds.len(),
                "method_bounds_sha256": sha256(&Value::Array(bounds)),
            })
        }
    }
}

/// `re.escape` of a str.
fn re_escape(s: &[u16]) -> Vec<u16> {
    const SPECIAL: &[u8] = b"()[]{}?*+-|^$\\.&~# \t\n\r\x0b\x0c";
    let mut out = Vec::with_capacity(s.len());
    for &u in s {
        if u8::try_from(u).is_ok_and(|b| SPECIAL.contains(&b)) {
            out.push(u16::from(b'\\'));
        }
        out.push(u);
    }
    out
}

/// Member 0 as `(class descriptor, name)`, or None when the table is empty or
/// member 0 does not resolve.
fn sample(dex: &Dex<'_>, kind: MemberKind) -> Option<(Vec<u16>, Vec<u16>)> {
    let (class_idx, name_idx) = match kind {
        MemberKind::Method => {
            let m = dex.get_method(0).ok()?;
            (m.class_idx, m.name_idx)
        }
        MemberKind::Field => {
            let f = dex.get_field(0).ok()?;
            (f.class_idx, f.name_idx)
        }
    };
    let (_, class) = dex.get_type(usize::from(class_idx)).ok()?;
    let name = dex.get_string(name_idx as usize).ok()?;
    Some((class.descriptor.0, name.0))
}

fn query_list(buf: &[u8]) -> Vec<Query> {
    let mut queries: Vec<Query> = STRING_PATTERNS
        .iter()
        .map(|p| Query::String(units(p)))
        .collect();
    queries.extend(TYPE_PATTERNS.iter().map(|p| Query::Type(units(p))));
    let Ok(dex) = Dex::new(buf) else {
        return queries;
    };
    let count = dex.header.strings.1;
    if count > 0 {
        for idx in [0, count.saturating_sub(1)] {
            if let Ok(s) = dex.get_string(idx) {
                queries.push(Query::String(re_escape(&s)));
            }
        }
    }
    for (kind, wild, fuzzy) in [
        (MemberKind::Method, "view", "AccessibilityServiceInfo"),
        (MemberKind::Field, "action", "Notification"),
    ] {
        let wrap = |q: MemberQuery| match kind {
            MemberKind::Method => Query::Method(q),
            MemberKind::Field => Query::Field(q),
        };
        queries.push(wrap(MemberQuery {
            class: None,
            name: Some(units(wild)),
        }));
        let count = match kind {
            MemberKind::Method => dex.header.methods.1,
            MemberKind::Field => dex.header.fields.1,
        };
        let s = if count == 0 { None } else { sample(&dex, kind) };
        if let Some((cls, name)) = &s {
            queries.push(wrap(MemberQuery {
                class: Some((cls.clone(), true)),
                name: None,
            }));
            queries.push(wrap(MemberQuery {
                class: Some((cls.clone(), true)),
                name: Some(name.clone()),
            }));
        }
        queries.push(wrap(MemberQuery {
            class: Some((units(fuzzy), false)),
            name: None,
        }));
        if let Some((_, name)) = &s {
            queries.push(wrap(MemberQuery {
                class: Some((units(fuzzy), false)),
                name: Some(name.clone()),
            }));
        }
    }
    queries
}

fn encode_query(q: &Query) -> Value {
    match q {
        Query::String(s) | Query::Type(s) => json!(s),
        Query::Method(m) | Query::Field(m) => json!({
            "class": m.class.as_ref().map(|(c, precise)| json!([c, precise])),
            "name": m.name,
        }),
    }
}

fn run_query(buf: &[u8], name: &str, q: &Query) -> Value {
    let mut record = serde_json::Map::new();
    record.insert("kind".into(), json!(q.kind().as_str()));
    record.insert("query".into(), encode_query(q));
    let mut refs = match FindRefs::new(buf) {
        Ok(r) => r,
        Err(e) => {
            record.insert("error".into(), json!(e.to_string()));
            return Value::Object(record);
        }
    };
    let located = match refs.locate(q) {
        Ok(l) => l,
        Err(e) => {
            record.insert("error".into(), json!(e.to_string()));
            return Value::Object(record);
        }
    };
    record.insert(
        "located".into(),
        compact(located.iter().map(|&i| json!(i)).collect()),
    );
    if !located.is_empty() {
        match refs.scan(q.kind(), &located) {
            Err(e) => {
                record.insert("error".into(), json!(e.to_string()));
                return Value::Object(record);
            }
            Ok((scan, owners)) => {
                record.insert(
                    "offsets".into(),
                    compact(scan.offsets.iter().map(|&o| json!(o)).collect()),
                );
                record.insert(
                    "marks".into(),
                    compact(scan.marks.iter().map(|&m| json!(m)).collect()),
                );
                record.insert(
                    "mids".into(),
                    compact(
                        owners
                            .iter()
                            .map(|o| o.as_ref().map_or(Value::Null, owner_json))
                            .collect(),
                    ),
                );
            }
        }
    }
    let lines = match findrefs::findrefs(name, buf, q) {
        Ok(lines) => compact(lines.iter().map(|l| json!(l)).collect()),
        Err(e) => error(e),
    };
    record.insert("lines".into(), lines);
    Value::Object(record)
}

fn dump_dex(buf: &[u8], name: &str) -> Value {
    if let Err(e) = Dex::new(buf) {
        return json!({ "name": units(name), "dex_parse": error(e) });
    }
    let queries: Vec<Value> = query_list(buf)
        .iter()
        .map(|q| run_query(buf, name, q))
        .collect();
    json!({
        "name": units(name),
        "string_map": dump_string_map(buf),
        "type_map": dump_type_map(buf),
        "method_map": dump_member_map(buf, MemberKind::Method),
        "field_map": dump_member_map(buf, MemberKind::Field),
        "insn_map": dump_insn_map(buf),
        "queries": queries,
    })
}

/// The APK-level dump; the caller has checked existence and size.
pub fn dump_apk(apk: &[u8]) -> Value {
    let mut entries = match parse_cd_dex_entries(apk) {
        Ok(e) => e,
        Err(e) => return error(e),
    };
    entries.sort_by_key(|e| e.comp_size);
    let mut dex = Vec::new();
    for entry in &entries {
        let data = match inflate_entry(apk, entry, None) {
            Ok(d) => d.unwrap_or_default(),
            Err(e) => {
                dex.push(json!({ "name": units(&entry.name), "inflate": error(e) }));
                continue;
            }
        };
        for (logical_name, logical_buf) in iter_logical_dex_buffers(&entry.name, &data) {
            dex.push(dump_dex(&logical_buf, &logical_name));
        }
    }
    json!({ "dex": dex })
}
