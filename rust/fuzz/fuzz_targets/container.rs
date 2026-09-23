#![no_main]

use asc_core::dex::{
    dex041_logical_offsets, is_dex041_container, iter_logical_dex_buffers,
    normalize_dex041_logical,
};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = is_dex041_container(data);
    let offsets = dex041_logical_offsets(data);
    for &off in &offsets {
        let buf = normalize_dex041_logical(data, off);
        assert_eq!(buf.len(), data.len(), "logical buffers stay container-sized");
    }
    let logical = iter_logical_dex_buffers("classes.dex", data);
    assert!(!logical.is_empty());
});
