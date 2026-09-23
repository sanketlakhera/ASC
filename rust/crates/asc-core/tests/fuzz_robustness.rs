#![allow(clippy::unwrap_used, clippy::indexing_slicing)]

use asc_core::dex::{Dex, Header, dex_defines_class_raw, find_type_idx_raw};
use asc_core::inflate::inflate_entry;
use asc_core::leb128::{read_sleb128, read_uleb128, skip_uleb128, uleb128_len};
use asc_core::mutf8::{decode_mutf8, encode_mutf8};
use asc_core::zip::{DexEntry, find_eocd, parse_cd_dex_entries};
use proptest::prelude::*;

proptest! {
    #![proptest_config(ProptestConfig::with_cases(50))]

    #[test]
    fn fuzz_leb128_no_panic(data in prop::collection::vec(any::<u8>(), 0..256), pos in 0..300usize) {
        let _ = read_uleb128(&data, pos);
        let _ = read_sleb128(&data, pos);
        let _ = uleb128_len(&data, pos);
        let _ = skip_uleb128(&data, pos);
    }

    #[test]
    fn fuzz_mutf8_no_panic(data in prop::collection::vec(any::<u8>(), 0..512)) {
        let decoded = decode_mutf8(&data);
        let _ = decoded.to_string_lossy();
        let encoded = encode_mutf8(decoded.as_slice());
        let decoded2 = decode_mutf8(&encoded);
        assert_eq!(decoded, decoded2);
    }

    #[test]
    fn fuzz_zip_eocd_and_cd_no_panic(data in prop::collection::vec(any::<u8>(), 0..1024)) {
        if let Ok(eocd) = find_eocd(&data) {
            let _ = eocd.offset;
            let _ = eocd.cd_off;
            let _ = eocd.cd_size;
        }
        let _ = parse_cd_dex_entries(&data);
    }

    #[test]
    fn fuzz_inflate_no_panic(
        data in prop::collection::vec(any::<u8>(), 0..512),
        method in prop::sample::select(vec![0u16, 8u16, 1u16, 99u16]),
        usize_val in 0..1024u32,
        csize_val in 0..1024u32,
        local_hdr_off in 0..512u32,
    ) {
        let entry = DexEntry {
            name: "test.dex".to_string(),
            uncomp_size: usize_val,
            comp_size: csize_val,
            local_header_off: local_hdr_off,
            method,
        };
        let _ = inflate_entry(&data, &entry, None);
    }

    #[test]
    fn fuzz_dex_header_and_reader_no_panic(data in prop::collection::vec(any::<u8>(), 0..1024)) {
        let _ = Header::parse(&data);
        let _ = find_type_idx_raw(&data, b"LTest;");
        let _ = dex_defines_class_raw(&data, b"LTest;");
        if let Ok(dex) = Dex::new(&data) {
            let _ = dex.get_string(0);
            let _ = dex.get_type(0);
            let _ = dex.get_prototype(0);
            let _ = dex.get_field(0);
            let _ = dex.get_method(0);
            let _ = dex.get_class(0);
            let _ = dex.find_class("LTest;");
        }
    }
}
