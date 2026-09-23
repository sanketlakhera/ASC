#![allow(clippy::unwrap_used, clippy::indexing_slicing)]

use asc_core::dex::{Dex, TypeKind, dex041_logical_offsets, is_dex041_container, parse_descriptor};
use asc_core::error::AscError;
use asc_core::inflate::inflate_entry;
use asc_core::zip::parse_cd_dex_entries;
use std::fs;
use std::path::PathBuf;

fn corpus_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../conformance/corpus")
}

fn get_minimal_dex_bytes() -> Vec<u8> {
    let apk_path = corpus_dir().join("fixture_stored.apk");
    let apk_data = fs::read(apk_path).expect("failed to read fixture_stored.apk");
    let entries = parse_cd_dex_entries(&apk_data).expect("failed to parse zip entries");
    inflate_entry(&apk_data, &entries[0], None)
        .unwrap()
        .expect("failed to inflate classes.dex")
}

#[test]
fn test_dex_header_and_tables() {
    let dex_buf = get_minimal_dex_bytes();
    let dex = Dex::new(&dex_buf).expect("failed to parse dex header");

    assert!(dex.header.strings.1 > 0);
    assert!(dex.header.types.1 > 0);
    assert!(dex.header.classes.1 > 0);

    // Verify string 0
    let str0 = dex.get_string(0).expect("failed to get string 0");
    assert_eq!(str0.to_string_lossy(), "Lexample/Test;");

    // Verify type 0
    let (str_idx, type0) = dex.get_type(0).expect("failed to get type 0");
    assert_eq!(str_idx, 0);
    assert_eq!(type0.kind, TypeKind::Class);
    assert_eq!(type0.dim, 0);
    assert_eq!(type0.descriptor.to_string_lossy(), "Lexample/Test;");
}

#[test]
fn test_dex_classes_and_code_items() {
    let dex_buf = get_minimal_dex_bytes();
    let dex = Dex::new(&dex_buf).expect("failed to parse dex");

    let cls0 = dex.get_class(0).expect("failed to get class 0");
    assert_eq!(cls0.fullname.to_string_lossy(), "Lexample/Test;");
    assert_eq!(cls0.direct_methods.len(), 2);

    let method0 = &cls0.direct_methods[0];
    let code_off = method0[2] as usize;
    assert!(code_off > 0);

    let code_item = dex
        .get_code_item(code_off)
        .expect("failed to get code item");
    assert_eq!(code_item.registers_size, 1);
    assert_eq!(code_item.insns_size, 3);
    assert_eq!(code_item.insns_bytes.len(), 6);
}

#[test]
fn test_dex_find_and_defines_class() {
    let dex_buf = get_minimal_dex_bytes();
    let dex = Dex::new(&dex_buf).expect("failed to parse dex");

    // Existing class
    assert_eq!(dex.find_class("Lexample/Test;").unwrap(), Some(0));
    assert!(dex.defines_class(b"Lexample/Test;").unwrap());

    // Nonexistent classes
    assert_eq!(dex.find_class("Lnonexistent/Cls;").unwrap(), None);
    assert!(!dex.defines_class(b"Lnonexistent/Cls;").unwrap());
    assert_eq!(dex.find_class("Ldoes/not/Exist;").unwrap(), None);
    assert!(!dex.defines_class(b"Ldoes/not/Exist;").unwrap());
}

#[test]
fn test_dex_descriptor_parser() {
    let dex_buf = get_minimal_dex_bytes();
    let dex = Dex::new(&dex_buf).unwrap();

    // Void primitive type
    let (_idx, void_type) = dex.get_type(2).unwrap();
    assert_eq!(void_type.kind, TypeKind::Primitive(0));
    assert_eq!(void_type.dim, 0);
    assert_eq!(void_type.primitive_value, Some(0));

    // Synthetic array descriptor: [[I
    let array_desc = asc_core::mutf8::decode_mutf8(b"[[I");
    let array_type = parse_descriptor(&array_desc);
    assert_eq!(array_type.kind, TypeKind::Array);
    assert_eq!(array_type.dim, 2);
    assert_eq!(array_type.primitive_value, None);
}

#[test]
fn test_dex_corrupt_inputs() {
    // 1. Buffer too short (< 0x70)
    let short_buf = [0u8; 10];
    assert_eq!(
        Dex::new(&short_buf).err(),
        Some(AscError::BadDexMagicOrHeaderSize)
    );

    // 2. Bad magic
    let mut bad_magic = [0u8; 0x70];
    bad_magic[..3].copy_from_slice(b"foo");
    assert_eq!(
        Dex::new(&bad_magic).err(),
        Some(AscError::BadDexMagicOrHeaderSize)
    );

    // 3. Out of range string_ids
    let dex_buf = get_minimal_dex_bytes();
    let dex = Dex::new(&dex_buf).unwrap();
    assert_eq!(
        dex.get_string(9999).err(),
        Some(AscError::BadStringIdsRange)
    );
}

#[test]
fn test_dex041_container_detection() {
    let dex_buf = get_minimal_dex_bytes();
    assert!(!is_dex041_container(&dex_buf));
    assert_eq!(dex041_logical_offsets(&dex_buf), vec![0]);

    let d041_path = corpus_dir().join("fixture_dex041.apk");
    if d041_path.exists() {
        let apk_data = fs::read(d041_path).unwrap();
        let entries = parse_cd_dex_entries(&apk_data).unwrap();
        let inflated = inflate_entry(&apk_data, &entries[0], None)
            .unwrap()
            .unwrap();
        assert!(is_dex041_container(&inflated));
        let offsets = dex041_logical_offsets(&inflated);
        assert!(offsets.len() > 1);
    }
}
