use asc_core::error::AscError;
use asc_core::zip::{decode_utf8_ignore, find_eocd, parse_cd_dex_entries};
use serde::Deserialize;
use std::fs;
use std::path::PathBuf;

#[derive(Deserialize)]
struct ZipNameCase {
    input_hex: String,
    decoded_ignore: String,
}

fn hex_decode(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

fn corpus_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../conformance/corpus")
}

#[test]
fn test_zip_names_vectors() {
    let vector_path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../conformance/vectors/zip_names.json"
    );
    let data = fs::read_to_string(vector_path).expect("failed to read zip_names.json");
    let cases: Vec<ZipNameCase> =
        serde_json::from_str(&data).expect("failed to parse zip_names.json");

    for (idx, case) in cases.iter().enumerate() {
        let bytes = hex_decode(&case.input_hex);
        let decoded = decode_utf8_ignore(&bytes);
        assert_eq!(
            decoded, case.decoded_ignore,
            "mismatch on zip name case {idx} (hex: {})",
            case.input_hex
        );
    }
}

#[test]
fn test_corrupt_apk_fixtures() {
    let c_dir = corpus_dir();

    // 1. Corrupt empty APK
    let empty_path = c_dir.join("fixture_corrupt_empty.apk");
    if empty_path.exists() {
        let empty_data = fs::read(&empty_path).unwrap();
        assert_eq!(find_eocd(&empty_data), Err(AscError::EocdNotFound));
        assert_eq!(
            parse_cd_dex_entries(&empty_data),
            Err(AscError::EocdNotFound)
        );
    }

    // 2. Corrupt EOCD APK
    let eocd_path = c_dir.join("fixture_corrupt_eocd.apk");
    if eocd_path.exists() {
        let eocd_data = fs::read(&eocd_path).unwrap();
        assert_eq!(find_eocd(&eocd_data), Err(AscError::BadEocdHeader));
        assert_eq!(
            parse_cd_dex_entries(&eocd_data),
            Err(AscError::BadEocdHeader)
        );
    }

    // 3. Corrupt CD APK
    let cd_path = c_dir.join("fixture_corrupt_cd.apk");
    if cd_path.exists() {
        let cd_data = fs::read(&cd_path).unwrap();
        assert_eq!(
            parse_cd_dex_entries(&cd_data),
            Err(AscError::BadCentralDirectoryRange)
        );
    }
}

#[test]
fn test_corpus_apk_zip_entries() {
    let c_dir = corpus_dir();
    let sample = c_dir.join("fixture_stored.apk");
    assert!(sample.exists(), "fixture_stored.apk should exist");
    let data = fs::read(&sample).unwrap();
    let entries = parse_cd_dex_entries(&data).expect("failed to parse entries");
    assert!(!entries.is_empty());
    assert_eq!(entries[0].name, "classes.dex");
    assert_eq!(entries[0].method, 0); // stored
}
