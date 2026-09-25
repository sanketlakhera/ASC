#![no_main]

//! Arbitrary DEX bytes: the class_data walk and bucket table, then a scan of
//! every reference kind for ids 0..64 and the instruction-walk verification of
//! every hit. Only panics, OOM and timeouts are findings.

use asc_core::dex::{Dex, iter_logical_dex_buffers};
use asc_core::findrefs::insn::InsnLocator;
use asc_core::findrefs::scan::{self, RefKind};
use libfuzzer_sys::fuzz_target;
use std::collections::BTreeSet;

fn walk(buf: &[u8]) {
    let Ok(dex) = Dex::new(buf) else {
        return;
    };
    let Ok(insn) = InsnLocator::parse(&dex) else {
        return;
    };
    let ids: BTreeSet<u32> = (0..64).collect();
    for kind in [RefKind::String, RefKind::Type, RefKind::Field, RefKind::Method] {
        let hits = scan::scan(buf, insn.code_range(), kind, &ids);
        let owners = insn.verify(buf, &hits.offsets);
        assert_eq!(owners.len(), hits.offsets.len());
    }
    let _ = insn.bucket_count();
    let _ = insn.bounds();
}

fuzz_target!(|data: &[u8]| {
    for (_, buf) in iter_logical_dex_buffers("classes.dex", data) {
        walk(&buf);
    }
});
