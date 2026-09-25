#![allow(clippy::unwrap_used, clippy::indexing_slicing)]
//! Ports of the Python findrefs tests (`tests/test_references.py`, the string
//! attribution and error contracts of `tests/test_oracle_contract.py`) on the
//! same `make_dex()` fixture, patched the same way.

use asc_core::AscError;
use asc_core::dex::Dex;
use asc_core::findrefs::insn::{InsnLocator, Owner, Walk};
use asc_core::findrefs::scan::{self, RefKind};
use asc_core::findrefs::string::StringLocator;
use asc_core::findrefs::{self, Query};
use asc_core::inflate::inflate_entry;
use asc_core::zip::parse_cd_dex_entries;
use std::collections::BTreeSet;

/// `make_dex()`: the stored fixture's classes.dex.
fn make_dex() -> Vec<u8> {
    let path = format!(
        "{}/../../conformance/corpus/fixture_stored.apk",
        env!("CARGO_MANIFEST_DIR")
    );
    let apk = std::fs::read(path).unwrap();
    let entries = parse_cd_dex_entries(&apk).unwrap();
    inflate_entry(&apk, &entries[0], None).unwrap().unwrap()
}

fn u32_at(b: &[u8], off: usize) -> usize {
    u32::from_le_bytes(b[off..off + 4].try_into().unwrap()) as usize
}

fn put_u32(b: &mut [u8], off: usize, v: u32) {
    b[off..off + 4].copy_from_slice(&v.to_le_bytes());
}

fn units(s: &str) -> Vec<u16> {
    s.encode_utf16().collect()
}

/// `ReferenceTests.search`: scan for string 5 and verify.
fn search(data: &[u8]) -> Vec<Option<Owner>> {
    let dex = Dex::new(data).unwrap();
    let insn = InsnLocator::parse(&dex).unwrap();
    let hits = scan::scan(
        data,
        insn.code_range(),
        RefKind::String,
        &BTreeSet::from([5]),
    );
    insn.verify(data, &hits.offsets)
}

fn mids(owner: &Option<Owner>) -> BTreeSet<u64> {
    owner.as_ref().unwrap().mids().iter().copied().collect()
}

#[test]
fn shared_code_keeps_method_zero() {
    let results = search(&make_dex());
    assert_eq!(results.len(), 1);
    assert_eq!(mids(&results[0]), BTreeSet::from([0, 1]));
    // the later method is listed first: locate verifies against it
    assert_eq!(results[0], Some(Owner::Many(vec![1, 0])));
}

#[test]
fn repeated_scans_give_the_same_owner() {
    let data = make_dex();
    let dex = Dex::new(&data).unwrap();
    let insn = InsnLocator::parse(&dex).unwrap();
    let bounds = insn.bounds();
    for _ in 0..2 {
        let hits = scan::scan(
            &data,
            insn.code_range(),
            RefKind::String,
            &BTreeSet::from([5]),
        );
        let owners = insn.verify(&data, &hits.offsets);
        assert_eq!(owners, vec![Some(Owner::Many(vec![1, 0]))]);
        assert_eq!(insn.bounds(), bounds);
    }
}

fn map_entries(data: &[u8]) -> Vec<usize> {
    let map_off = u32_at(data, 52);
    let count = u32_at(data, map_off);
    (0..count).map(|i| map_off + 4 + i * 12).collect()
}

#[test]
fn fallback_without_class_data_map_entry() {
    let mut data = make_dex();
    for off in map_entries(&data) {
        if data[off..off + 2] == [0x00, 0x20] {
            data[off..off + 2].copy_from_slice(&0xffffu16.to_le_bytes());
        }
    }
    let dex = Dex::new(&data).unwrap();
    assert_eq!(InsnLocator::parse(&dex).unwrap().walk, Walk::Def);
    assert_eq!(mids(&search(&data)[0]), BTreeSet::from([0, 1]));
}

#[test]
fn empty_or_absent_map_uses_class_definitions() {
    for empty in [true, false] {
        let mut data = make_dex();
        let map_off = u32_at(&data, 52);
        put_u32(&mut data, if empty { map_off } else { 52 }, 0);
        let dex = Dex::new(&data).unwrap();
        assert_eq!(InsnLocator::parse(&dex).unwrap().walk, Walk::Def);
        assert_eq!(mids(&search(&data)[0]), BTreeSet::from([0, 1]));
    }
}

#[test]
fn class_without_method_bodies_has_no_references() {
    let mut data = make_dex();
    let class_off = u32_at(&data, 100);
    let class_data = u32_at(&data, class_off + 24);
    data[class_data..class_data + 10].copy_from_slice(b"\0\0\x02\0\0\x09\0\x01\x09\0");
    assert!(search(&data).is_empty());
    let dex = Dex::new(&data).unwrap();
    assert_eq!(InsnLocator::parse(&dex).unwrap().code_range(), (0, 0));
}

fn locate(data: &[u8], q: &str) -> BTreeSet<u32> {
    let dex = Dex::new(data).unwrap();
    StringLocator::build(&dex)
        .unwrap()
        .locate(data, &units(q))
        .unwrap()
}

#[test]
fn last_string_is_searchable() {
    assert_eq!(locate(&make_dex(), "token"), BTreeSet::from([5]));
}

#[test]
fn empty_string_table() {
    let mut data = make_dex();
    put_u32(&mut data, 56, 0);
    put_u32(&mut data, 60, 0);
    assert_eq!(locate(&data, "token"), BTreeSet::new());
}

// M2 F1 / F2: StringAttributionTests

#[test]
fn empty_pattern_matches_nothing() {
    assert_eq!(locate(&make_dex(), ""), BTreeSet::new());
}

#[test]
fn match_through_the_final_terminator_belongs_to_no_string() {
    assert_eq!(locate(&make_dex(), "token."), BTreeSet::new());
    assert_eq!(locate(&make_dex(), "token\\x00"), BTreeSet::new());
}

#[test]
fn match_through_a_terminator_belongs_to_the_next_string() {
    assert_eq!(locate(&make_dex(), "first..s"), BTreeSet::from([4]));
}

#[test]
fn every_string_is_reachable() {
    assert_eq!(locate(&make_dex(), "."), (0..6).collect());
}

/// `StringAttributionTests.permute`: string_data rewritten in place in `order`.
fn permute(raw: &[u8], order: &[usize]) -> Vec<u8> {
    let mut raw = raw.to_vec();
    let ids_off = u32_at(&raw, 0x3C);
    let offs: Vec<usize> = (0..order.len())
        .map(|i| u32_at(&raw, ids_off + 4 * i))
        .collect();
    let last = offs[offs.len() - 1];
    let end = raw[last + 1..].iter().position(|&b| b == 0).unwrap() + last + 2;
    let mut bounds = offs.clone();
    bounds.push(end);
    let items: Vec<Vec<u8>> = (0..offs.len())
        .map(|i| raw[bounds[i]..bounds[i + 1]].to_vec())
        .collect();
    let mut pos = offs[0];
    for &idx in order {
        raw[pos..pos + items[idx].len()].copy_from_slice(&items[idx]);
        put_u32(&mut raw, ids_off + 4 * idx, pos as u32);
        pos += items[idx].len();
    }
    raw
}

#[test]
fn string_data_out_of_string_ids_order() {
    let raw = permute(&make_dex(), &[5, 3, 4, 0, 1, 2]);
    assert_eq!(locate(&raw, "token"), BTreeSet::from([5]));
    assert_eq!(locate(&raw, "first"), BTreeSet::from([3]));
    assert_eq!(locate(&raw, "Object"), BTreeSet::from([1]));
    assert_eq!(locate(&raw, "first..s"), BTreeSet::from([4]));
    assert_eq!(locate(&raw, "V"), BTreeSet::from([2]));
    assert_eq!(locate(&raw, "V."), BTreeSet::new());
}

#[test]
fn duplicate_offsets_resolve_to_the_highest_index() {
    let mut raw = make_dex();
    let ids_off = u32_at(&raw, 0x3C);
    let first = u32_at(&raw, ids_off + 12) as u32;
    put_u32(&mut raw, ids_off + 16, first);
    assert_eq!(locate(&raw, "first"), BTreeSet::from([4]));
}

// AscHandler.findrefs lines

#[test]
fn search_lines_for_shared_code() {
    let lines =
        findrefs::findrefs("fixture.dex", &make_dex(), &Query::String(units("token"))).unwrap();
    let text: Vec<String> = lines
        .iter()
        .map(|l| String::from_utf16(l).unwrap())
        .collect();
    assert_eq!(
        text,
        [
            "fixture.dex | Lexample/Test;->first | matched=(token)",
            "fixture.dex | Lexample/Test;->second | matched=(token)",
        ]
    );
}

/// A corrupt code_item is only noticed once something matched (the
/// instruction map is built lazily), as in Python.
#[test]
fn insns_past_the_end_fail_only_when_needed() {
    let mut raw = make_dex();
    let header = [1u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3, 0, 0, 0];
    let at = raw.windows(16).position(|w| w == header).unwrap();
    put_u32(&mut raw, at + 12, 0x7777_7777);
    let nothing = findrefs::findrefs("classes.dex", &raw, &Query::String(units("zzz_nomatch")));
    assert_eq!(nothing.unwrap(), Vec::<Vec<u16>>::new());
    let err = findrefs::findrefs("classes.dex", &raw, &Query::String(units("token")));
    assert_eq!(err.unwrap_err(), AscError::BadCodeItemOffset);
}

// Property tests (plan 4.1, 4.6)

mod properties {
    use super::*;
    use proptest::prelude::*;

    /// A buffer with just what `StringLocator` reads: header, string_ids, data.
    fn string_dex(strings: &[Vec<u8>]) -> Vec<u8> {
        let mut buf = vec![0u8; 0x70];
        buf[..8].copy_from_slice(b"dex\n035\0");
        let ids_off = buf.len();
        put_u32(&mut buf, 0x38, strings.len() as u32);
        put_u32(&mut buf, 0x3C, ids_off as u32);
        buf.resize(ids_off + 4 * strings.len(), 0);
        for (i, s) in strings.iter().enumerate() {
            let at = buf.len() as u32;
            put_u32(&mut buf, ids_off + 4 * i, at);
            buf.push(s.len() as u8);
            buf.extend_from_slice(s);
            buf.push(0);
        }
        buf
    }

    proptest! {
        /// A literal query that cannot cross a NUL finds exactly the strings
        /// containing it. Lengths stay below 0x30 so no uleb prefix byte is a
        /// letter or digit a match could start on.
        #[test]
        fn literal_query_finds_the_strings_containing_it(
            strings in prop::collection::vec("[a-e]{0,12}", 1..40),
            query in "[a-e]{1,3}",
        ) {
            let raw: Vec<Vec<u8>> = strings.iter().map(|s| s.clone().into_bytes()).collect();
            let buf = string_dex(&raw);
            let dex = Dex::new(&buf).unwrap();
            let found = StringLocator::build(&dex).unwrap().locate(&buf, &units(&query)).unwrap();
            let expected: BTreeSet<u32> = strings
                .iter()
                .enumerate()
                .filter(|(_, s)| s.contains(query.as_str()))
                .map(|(i, _)| i as u32)
                .collect();
            prop_assert_eq!(found, expected);
        }

        /// The scanner against a naive loop over every position and opcode,
        /// for every kind (the string kind takes the memchr2 path).
        #[test]
        fn scan_matches_a_naive_loop(
            region in prop::collection::vec(any::<u8>(), 0..400),
            ids in prop::collection::btree_set(0u32..300, 0..20),
            start in 0usize..8,
            slack in 0usize..20,
        ) {
            let end = region.len() + slack;
            for kind in [RefKind::String, RefKind::Type, RefKind::Field, RefKind::Method] {
                let got = scan::scan(&region, (start, end), kind, &ids);
                let mut offsets = Vec::new();
                let mut marks = Vec::new();
                let end = end.min(region.len());
                for p in start..end {
                    let width = match (kind, region[p]) {
                        (RefKind::String, 0x1a) => 2,
                        (RefKind::String, 0x1b) => 4,
                        (RefKind::Type, 0x1c | 0x1f | 0x20 | 0x22 | 0x23 | 0x24 | 0x25) => 2,
                        (RefKind::Field, 0x52..=0x6d) => 2,
                        (RefKind::Method, 0x6e..=0x72 | 0x74..=0x78 | 0xfa | 0xfb) => 2,
                        _ => continue,
                    };
                    if p + 2 + width > end {
                        continue;
                    }
                    let mut id = 0u32;
                    for (i, &b) in region[p + 2..p + 2 + width].iter().enumerate() {
                        id |= u32::from(b) << (8 * i);
                    }
                    if ids.contains(&id) {
                        offsets.push(p);
                        marks.push(id);
                    }
                }
                prop_assert_eq!(&got.offsets, &offsets, "{:?}", kind);
                prop_assert_eq!(&got.marks, &marks, "{:?}", kind);
            }
        }
    }
}
