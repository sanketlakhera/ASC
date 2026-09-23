#![no_main]

use asc_core::dex::Header;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = Header::parse(data);
});
