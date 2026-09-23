#![allow(clippy::unwrap_used, clippy::indexing_slicing)]

use asc_core::mutf8::{decode_mutf8, encode_mutf8, utf16_len};
use proptest::prelude::*;
use serde::Deserialize;

#[derive(Deserialize)]
struct DecodeCase {
    input_hex: String,
    units: Vec<u16>,
}

#[derive(Deserialize)]
struct EncodeCase {
    units: Vec<u16>,
    encoded_hex: String,
    utf16_len: usize,
}

#[derive(Deserialize)]
struct Mutf8Vectors {
    decode: Vec<DecodeCase>,
    encode: Vec<EncodeCase>,
}

mod hex {
    pub fn decode(s: &str) -> Result<Vec<u8>, ()> {
        if !s.len().is_multiple_of(2) {
            return Err(());
        }
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(|_| ()))
            .collect()
    }

    pub fn encode(b: &[u8]) -> String {
        b.iter().map(|byte| format!("{byte:02x}")).collect()
    }
}

#[test]
fn test_mutf8_decode_vectors() {
    let vector_path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../conformance/vectors/mutf8.json"
    );
    let data = std::fs::read_to_string(vector_path).expect("failed to read mutf8.json");
    let vectors: Mutf8Vectors = serde_json::from_str(&data).expect("failed to parse mutf8.json");

    for (idx, case) in vectors.decode.iter().enumerate() {
        let bytes = hex::decode(&case.input_hex).expect("invalid hex in vector");
        let decoded = decode_mutf8(&bytes);
        assert_eq!(
            decoded.as_slice(),
            case.units.as_slice(),
            "decode mismatch on case {idx} (hex: {})",
            case.input_hex
        );
    }
}

#[test]
fn test_mutf8_encode_vectors() {
    let vector_path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../conformance/vectors/mutf8.json"
    );
    let data = std::fs::read_to_string(vector_path).expect("failed to read mutf8.json");
    let vectors: Mutf8Vectors = serde_json::from_str(&data).expect("failed to parse mutf8.json");

    for (idx, case) in vectors.encode.iter().enumerate() {
        let encoded = encode_mutf8(&case.units);
        let encoded_hex = hex::encode(&encoded);
        assert_eq!(
            encoded_hex, case.encoded_hex,
            "encode mismatch on case {idx}"
        );
        assert_eq!(
            utf16_len(&case.units),
            case.utf16_len,
            "utf16_len mismatch on case {idx}"
        );
    }
}

#[test]
fn test_mutf8_contract_cases() {
    // Ported from Mutf8Tests in test_oracle_contract.py
    let emoji = "\u{1F600}";
    let emoji_mutf8 = b"\xed\xa0\xbd\xed\xb8\x80";
    let mixed_mutf8 = b"tok\xc0\x80en\xed\xa0\xbd\xed\xb8\x80\xc3\xa9";

    // abc -> 3 units
    let s_abc = decode_mutf8(b"abc");
    assert_eq!(encode_mutf8(&s_abc), b"abc");
    assert_eq!(s_abc.utf16_len(), 3);

    // a\0b -> a\xC0\x80b
    let s_nul = decode_mutf8(b"a\xc0\x80b");
    assert_eq!(encode_mutf8(&s_nul), b"a\xc0\x80b");
    assert_eq!(s_nul.as_slice(), &[b'a' as u16, 0x0000, b'b' as u16]);

    // emoji
    let s_emoji = decode_mutf8(emoji_mutf8);
    assert_eq!(encode_mutf8(&s_emoji), emoji_mutf8);
    assert_eq!(s_emoji.utf16_len(), 2);
    assert_eq!(s_emoji.to_string_lossy(), emoji);

    // mixed
    let s_mixed = decode_mutf8(mixed_mutf8);
    assert_eq!(encode_mutf8(&s_mixed), mixed_mutf8);
    assert_eq!(s_mixed.utf16_len(), 9);

    // malformed input replacement: b"\xff\xfe" -> "\u{FFFD}\u{FFFD}"
    let s_malformed = decode_mutf8(b"\xff\xfe");
    assert_eq!(s_malformed.as_slice(), &[0xfffd, 0xfffd]);
}

proptest! {
    #[test]
    fn prop_mutf8_ascii_roundtrip(s in "[a-zA-Z0-9_-]{0,50}") {
        let bytes = s.as_bytes();
        let decoded = decode_mutf8(bytes);
        let encoded = encode_mutf8(&decoded);
        prop_assert_eq!(encoded, bytes);
    }
}
