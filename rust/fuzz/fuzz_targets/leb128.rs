#![no_main]

use asc_core::leb128::{read_sleb128, read_uleb128, skip_uleb128, uleb128_len};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // First byte picks the start position so reads near the end are covered.
    let Some((&pos, buf)) = data.split_first() else {
        return;
    };
    let pos = usize::from(pos);
    let _ = read_uleb128(buf, pos);
    let _ = read_sleb128(buf, pos);
    let _ = uleb128_len(buf, pos);
    let _ = skip_uleb128(buf, pos);
});
