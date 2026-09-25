#![allow(clippy::unwrap_used, clippy::indexing_slicing)]
//! The reference workload's 16 findrefs counts (`tests/fixtures/reference-baseline.json`),
//! computed the way `test_findrefs.py` in the reference archive computes them.

use asc_core::dex::Dex;
use asc_core::findrefs::insn::{InsnLocator, Owner};
use asc_core::findrefs::member::{MemberKind, MemberLocator, MemberQuery};
use asc_core::findrefs::scan::{self, RefKind};
use asc_core::findrefs::string::StringLocator;
use asc_core::findrefs::types::TypeLocator;
use asc_core::inflate::inflate_entry;
use asc_core::zip::parse_cd_dex_entries;
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};

fn units(s: &str) -> Vec<u16> {
    s.encode_utf16().collect()
}

fn fixture(name: &str) -> Vec<u8> {
    let path = format!(
        "{}/../../../tests/fixtures/{name}",
        env!("CARGO_MANIFEST_DIR")
    );
    std::fs::read(&path).unwrap_or_else(|e| panic!("{path}: {e}"))
}

fn workload_dex() -> Vec<u8> {
    let zip = fixture("reference-workload.zip");
    let entries = parse_cd_dex_entries(&zip).unwrap();
    let entry = entries.iter().find(|e| e.name == "classes.dex").unwrap();
    inflate_entry(&zip, entry, None).unwrap().unwrap()
}

/// `(class descriptor, name)` of member 0, as `DexMethod(dex, 0)` / `DexField(dex, 0)`.
fn sample(dex: &Dex<'_>, kind: MemberKind) -> (Vec<u16>, Vec<u16>) {
    let (class_idx, name_idx) = match kind {
        MemberKind::Method => {
            let m = dex.get_method(0).unwrap();
            (m.class_idx, m.name_idx)
        }
        MemberKind::Field => {
            let f = dex.get_field(0).unwrap();
            (f.class_idx, f.name_idx)
        }
    };
    let class = dex.get_type(usize::from(class_idx)).unwrap().1.descriptor.0;
    (class, dex.get_string(name_idx as usize).unwrap().0)
}

#[test]
fn reference_counts_match_the_baseline() {
    let baseline: Value = serde_json::from_slice(&fixture("reference-baseline.json")).unwrap();
    let expected: BTreeMap<String, u64> = baseline["findrefs_counts"]
        .as_object()
        .unwrap()
        .iter()
        .map(|(k, v)| (k.clone(), v.as_u64().unwrap()))
        .collect();

    let buf = workload_dex();
    let dex = Dex::new(&buf).unwrap();
    let insn = InsnLocator::parse(&dex).unwrap();
    let strings = StringLocator::build(&dex).unwrap();
    let types = TypeLocator::build(&dex).unwrap();
    let range = insn.code_range();
    // scan["kind"] after CodeItemScanner.scan: one entry per hit, verified or None
    let scanned = |kind: RefKind, ids: &BTreeSet<u32>| {
        let hits = scan::scan(&buf, range, kind, ids);
        insn.verify(&buf, &hits.offsets)
    };

    let mut got: BTreeMap<String, u64> = BTreeMap::new();
    let mut put = |k: &str, v: usize| {
        got.insert(k.to_string(), v as u64);
    };

    let created = strings.locate(&buf, &units("create")).unwrap();
    let string_scan = scanned(RefKind::String, &created);
    put("string_ref_count", string_scan.len());
    // `if not mid: continue` skips None and method 0
    put(
        "string_ref_class_count",
        string_scan
            .iter()
            .filter(|o| !matches!(o, None | Some(Owner::One(0))))
            .count(),
    );

    for (kind, label, wild, fuzzy, ref_kind) in [
        (
            MemberKind::Method,
            "method",
            "view",
            "AccessibilityServiceInfo",
            RefKind::Method,
        ),
        (
            MemberKind::Field,
            "field",
            "action",
            "Notification",
            RefKind::Field,
        ),
    ] {
        let members = MemberLocator::build(&dex, kind).unwrap();
        let (sample_class, sample_name) = sample(&dex, kind);
        let locate = |class: Option<(Vec<u16>, bool)>, name: Option<Vec<u16>>| {
            members
                .locate(&dex, &strings, &types, &MemberQuery { class, name })
                .unwrap()
        };
        let member = if label == "method" { "method" } else { "field" };
        put(
            &format!("{label}_locator_none_class Count"),
            locate(None, Some(units(wild))).len(),
        );
        put(
            &format!("{label}_locator_precise_class_only Count"),
            locate(Some((sample_class.clone(), true)), None).len(),
        );
        let precise = locate(
            Some((sample_class.clone(), true)),
            Some(sample_name.clone()),
        );
        put(
            &format!("{label}_locator_precise_class_{member} Count"),
            precise.len(),
        );
        put(
            &format!("{label}_locator_fuzzy_class_only Count"),
            locate(Some((units(fuzzy), false)), None).len(),
        );
        put(
            &format!("{label}_locator_fuzzy_class_{member} Count"),
            locate(Some((units(fuzzy), false)), Some(sample_name)).len(),
        );
        put(
            &format!("{label}_ref_count"),
            scanned(ref_kind, &precise).len(),
        );
    }

    let views = types.locate(&strings, &buf, &units("View")).unwrap();
    put("type_locator Count", views.len());
    put("type_ref_count", scanned(RefKind::Type, &views).len());

    assert_eq!(got, expected);
}
