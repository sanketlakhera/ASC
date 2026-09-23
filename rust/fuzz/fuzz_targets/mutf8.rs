#![no_main]

use asc_core::mutf8::{decode_mutf8, encode_mutf8, utf16_len};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let decoded = decode_mutf8(data);
    let _ = decoded.to_string_lossy();
    let _ = utf16_len(decoded.as_slice());
    // Encoding is total and decoding its output must give the same units back.
    let encoded = encode_mutf8(decoded.as_slice());
    assert_eq!(decode_mutf8(&encoded), decoded);
});
