//! `asc bench-findrefs DEX`: the reference workload's `test_findrefs.py`,
//! stage for stage, printing the same `[DEBUG] <stage> Time: <us> us` and
//! count lines so `tests/benchmark_compare.py --candidate-bin` can pair them
//! with Python's. Each stage builds what the Python stage builds lazily (the
//! method map in the first method case, the type map in the first fuzzy one).

use asc_core::dex::Dex;
use asc_core::findrefs::insn::{InsnLocator, Owner};
use asc_core::findrefs::member::{MemberKind, MemberLocator, MemberQuery};
use asc_core::findrefs::scan::{self, RefKind};
use asc_core::findrefs::string::StringLocator;
use asc_core::findrefs::types::TypeLocator;
use std::collections::BTreeSet;
use std::path::Path;
use std::time::Instant;

fn units(s: &str) -> Vec<u16> {
    s.encode_utf16().collect()
}

fn time(stage: &str, t: Instant) {
    println!(
        "[DEBUG] {stage} Time: {:.2} us",
        t.elapsed().as_secs_f64() * 1e6
    );
}

fn count(name: &str, n: usize) {
    println!("[DEBUG] {name}: {n}");
}

fn sample(dex: &Dex<'_>, kind: MemberKind) -> Option<(Vec<u16>, Vec<u16>)> {
    let (class_idx, name_idx) = match kind {
        MemberKind::Method => dex.get_method(0).ok().map(|m| (m.class_idx, m.name_idx))?,
        MemberKind::Field => dex.get_field(0).ok().map(|f| (f.class_idx, f.name_idx))?,
    };
    let class = dex.get_type(usize::from(class_idx)).ok()?.1.descriptor.0;
    Some((class, dex.get_string(name_idx as usize).ok()?.0))
}

pub fn run(path: &Path) -> Result<(), String> {
    // The DEX is read into memory, as the CLI holds an inflated entry; the read
    // counts toward the first stage, where the script's open does.
    let t = Instant::now();
    let data = std::fs::read(path).map_err(|e| e.to_string())?;
    let buf: &[u8] = &data;
    let dex = Dex::new(buf).map_err(|e| e.to_string())?;
    let insn = InsnLocator::parse(&dex).map_err(|e| e.to_string())?;
    time("insn_locator", t);

    let t = Instant::now();
    let strings = StringLocator::build(&dex).map_err(|e| e.to_string())?;
    let created = strings
        .locate(buf, &units("create"))
        .map_err(|e| e.to_string())?;
    time("string_locator", t);

    let range = insn.code_range();
    let scanned = |kind: RefKind, ids: &BTreeSet<u32>| {
        let hits = scan::scan(buf, range, kind, ids);
        insn.verify(buf, &hits.offsets)
    };
    let t = Instant::now();
    let string_scan = scanned(RefKind::String, &created);
    time("code_scan", t);
    count("string_ref_count", string_scan.len());

    let t = Instant::now();
    let mut classes = Vec::new();
    for owner in &string_scan {
        let Some(Owner::One(mid)) = owner else {
            continue;
        };
        if *mid == 0 {
            continue;
        }
        if let Ok(m) = dex.get_method(*mid as usize)
            && let Ok((_, ty)) = dex.get_type(usize::from(m.class_idx))
        {
            classes.push(ty.descriptor);
        }
    }
    time("dexmethod", t);
    count("string_ref_class_count", classes.len());

    // Python builds the type map in the first fuzzy-class case; here it is
    // built as the method stage starts, so it counts toward the same total.
    let mut types: Option<TypeLocator> = None;
    let mut precise = [BTreeSet::new(), BTreeSet::new()];
    for (slot, kind, label, wild, fuzzy) in [
        (
            0,
            MemberKind::Method,
            "method",
            "view",
            "AccessibilityServiceInfo",
        ),
        (1, MemberKind::Field, "field", "action", "Notification"),
    ] {
        let t_all = Instant::now();
        if types.is_none() {
            types = Some(TypeLocator::build(&dex).map_err(|e| e.to_string())?);
        }
        let tl = types.as_ref().ok_or("type map")?;
        let (sample_class, sample_name) = sample(&dex, kind).unwrap_or_default();
        let mut members: Option<MemberLocator> = None;
        let mut case = |name: &str,
                        class: Option<(Vec<u16>, bool)>,
                        member: Option<Vec<u16>>|
         -> Result<BTreeSet<u32>, String> {
            let t = Instant::now();
            if members.is_none() {
                members = Some(MemberLocator::build(&dex, kind).map_err(|e| e.to_string())?);
            }
            let found = members
                .as_ref()
                .ok_or("member map")?
                .locate(
                    &dex,
                    &strings,
                    tl,
                    &MemberQuery {
                        class,
                        name: member,
                    },
                )
                .map_err(|e| e.to_string())?;
            time(&format!("{label}_locator_{name}"), t);
            count(&format!("{label}_locator_{name} Count"), found.len());
            Ok(found)
        };
        case("none_class", None, Some(units(wild)))?;
        case(
            "precise_class_only",
            Some((sample_class.clone(), true)),
            None,
        )?;
        precise[slot] = case(
            &format!("precise_class_{label}"),
            Some((sample_class.clone(), true)),
            Some(sample_name.clone()),
        )?;
        case("fuzzy_class_only", Some((units(fuzzy), false)), None)?;
        case(
            &format!("fuzzy_class_{label}"),
            Some((units(fuzzy), false)),
            Some(sample_name),
        )?;
        time(&format!("{label}_locator"), t_all);
    }

    let t = Instant::now();
    let method_scan = scanned(RefKind::Method, &precise[0]);
    time("method_ref_scan", t);
    count("method_ref_count", method_scan.len());

    let t = Instant::now();
    let field_scan = scanned(RefKind::Field, &precise[1]);
    time("field_ref_scan", t);
    count("field_ref_count", field_scan.len());

    let t = Instant::now();
    let tl = types.as_ref().ok_or("type map")?;
    let views = tl
        .locate(&strings, buf, &units("View"))
        .map_err(|e| e.to_string())?;
    time("type_locator", t);
    count("type_locator Count", views.len());

    let t = Instant::now();
    let type_scan = scanned(RefKind::Type, &views);
    time("type_ref_scan", t);
    count("type_ref_count", type_scan.len());
    Ok(())
}
