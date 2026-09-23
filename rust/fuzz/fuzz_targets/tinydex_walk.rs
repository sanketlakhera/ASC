#![no_main]

//! Parses the header and walks every table, every class_data and every code_item,
//! the way the primitive dump does. Only panics, OOM and timeouts are findings.

use asc_core::dex::{Dex, dex_defines_class_raw, find_type_idx_raw, iter_logical_dex_buffers};
use libfuzzer_sys::fuzz_target;

/// A table can hold at most one entry per byte of input, so a larger declared
/// size fails its bounds check before this cap and the walk stays linear.
fn walk_len(declared: usize, buf_len: usize) -> usize {
    declared.min(buf_len.saturating_add(1))
}

fn walk(buf: &[u8]) {
    let Ok(dex) = Dex::new(buf) else {
        return;
    };
    let h = dex.header;
    let n = buf.len();

    for i in 0..walk_len(h.strings.1, n) {
        if dex.get_string(i).is_err() {
            break;
        }
    }
    for i in 0..walk_len(h.types.1, n) {
        if dex.get_type(i).is_err() {
            break;
        }
    }
    for i in 0..walk_len(h.prototypes.1, n) {
        if dex.get_prototype(i).is_err() {
            break;
        }
    }
    for i in 0..walk_len(h.fields.1, n) {
        if dex.get_field(i).is_err() {
            break;
        }
    }
    for i in 0..walk_len(h.methods.1, n) {
        if dex.get_method(i).is_err() {
            break;
        }
    }
    for i in 0..walk_len(h.classes.1, n) {
        let Ok(class) = dex.get_class(i) else {
            break;
        };
        for m in class.direct_methods.iter().chain(&class.virtual_methods) {
            if m[2] != 0 {
                let _ = dex.get_code_item(m[2] as usize);
            }
        }
        let _ = dex.find_class_units(class.fullname.as_slice());
    }

    for q in [&b"Ljava/lang/Object;"[..], b"LTest;", b"", b"\xc0\x80"] {
        let _ = find_type_idx_raw(buf, q);
        let _ = dex_defines_class_raw(buf, q);
    }
}

fuzz_target!(|data: &[u8]| {
    for (_, buf) in iter_logical_dex_buffers("classes.dex", data) {
        walk(&buf);
    }
});
