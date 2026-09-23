#![no_main]

use asc_core::zip::{decode_utf8_ignore, find_eocd, parse_cd_dex_entries};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = find_eocd(data);
    let _ = parse_cd_dex_entries(data);
    let _ = decode_utf8_ignore(data);
});
