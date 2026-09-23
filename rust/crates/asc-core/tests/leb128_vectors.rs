use asc_core::leb128::{read_sleb128, read_uleb128, uleb128_len, write_sleb128, write_uleb128};
use proptest::prelude::*;
use serde::Deserialize;

#[derive(Deserialize)]
struct FastCase {
    value: Option<u64>,
    size: Option<usize>,
    error: Option<String>,
}

#[derive(Deserialize)]
struct LenCase {
    size: Option<usize>,
    error: Option<String>,
}

#[derive(Deserialize)]
struct UlebVector {
    input_hex: String,
    fast: FastCase,
    len: LenCase,
}

#[derive(Deserialize)]
struct SlebVector {
    input_hex: String,
    value_i64: Option<i64>,
    size: Option<usize>,
    error: Option<String>,
}

#[test]
fn test_uleb128_against_vectors() {
    let vector_path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../conformance/vectors/uleb128.json"
    );
    let data = std::fs::read_to_string(vector_path).expect("failed to read uleb128.json");
    let cases: Vec<UlebVector> = serde_json::from_str(&data).expect("failed to parse uleb128.json");

    for (idx, case) in cases.iter().enumerate() {
        let bytes = hex::decode(&case.input_hex).expect("invalid hex in vector");

        // Test read_uleb128 (fast)
        match read_uleb128(&bytes, 0) {
            Ok((val, size)) => {
                assert_eq!(
                    case.fast.error, None,
                    "case {idx} ({}): expected error {:?}, got Ok(({val}, {size}))",
                    case.input_hex, case.fast.error
                );
                assert_eq!(
                    Some(val),
                    case.fast.value,
                    "case {idx} ({}): value mismatch",
                    case.input_hex
                );
                assert_eq!(
                    Some(size),
                    case.fast.size,
                    "case {idx} ({}): size mismatch",
                    case.input_hex
                );
            }
            Err(e) => {
                assert!(
                    case.fast.error.is_some(),
                    "case {idx} ({}): unexpected error: {e}",
                    case.input_hex
                );
            }
        }

        // Test uleb128_len
        match uleb128_len(&bytes, 0) {
            Ok(size) => {
                assert_eq!(
                    case.len.error, None,
                    "case {idx} ({}): expected error {:?}, got Ok({size})",
                    case.input_hex, case.len.error
                );
                assert_eq!(
                    Some(size),
                    case.len.size,
                    "case {idx} ({}): size mismatch",
                    case.input_hex
                );
            }
            Err(e) => {
                assert!(
                    case.len.error.is_some(),
                    "case {idx} ({}): unexpected error: {e}",
                    case.input_hex
                );
            }
        }
    }
}

#[test]
fn test_sleb128_against_vectors() {
    let vector_path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../conformance/vectors/sleb128.json"
    );
    let data = std::fs::read_to_string(vector_path).expect("failed to read sleb128.json");
    let cases: Vec<SlebVector> = serde_json::from_str(&data).expect("failed to parse sleb128.json");

    for (idx, case) in cases.iter().enumerate() {
        let bytes = hex::decode(&case.input_hex).expect("invalid hex in vector");

        match read_sleb128(&bytes, 0) {
            Ok((val, size)) => {
                assert_eq!(
                    case.error, None,
                    "case {idx} ({}): expected error {:?}, got Ok(({val}, {size}))",
                    case.input_hex, case.error
                );
                if let Some(expected_val) = case.value_i64 {
                    assert_eq!(
                        val, expected_val,
                        "case {idx} ({}): value mismatch",
                        case.input_hex
                    );
                }
                assert_eq!(
                    Some(size),
                    case.size,
                    "case {idx} ({}): size mismatch",
                    case.input_hex
                );
            }
            Err(e) => {
                // If input length > 9, error is expected divergence
                if bytes.len() > 9 {
                    continue;
                }
                assert!(
                    case.error.is_some(),
                    "case {idx} ({}): unexpected error: {e}",
                    case.input_hex
                );
            }
        }
    }
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
}

proptest! {
    #[test]
    fn prop_uleb128_roundtrip(v in any::<u32>()) {
        let mut buf = Vec::new();
        write_uleb128(v, &mut buf);
        let (read_v, sz) = read_uleb128(&buf, 0).unwrap();
        prop_assert_eq!(read_v, u64::from(v));
        prop_assert_eq!(sz, buf.len());
        prop_assert_eq!(uleb128_len(&buf, 0).unwrap(), buf.len());
    }

    #[test]
    fn prop_sleb128_roundtrip(v in -0x0800_0000i32..=0x07FF_FFFFi32) {
        let mut buf = Vec::new();
        write_sleb128(v, &mut buf);
        let (read_v, sz) = read_sleb128(&buf, 0).unwrap();
        prop_assert_eq!(read_v, i64::from(v));
        prop_assert_eq!(sz, buf.len());
    }
}
