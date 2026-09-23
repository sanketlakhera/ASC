use asc_core::error::AscError;
use asc_core::inflate::inflate_entry;
use asc_core::zip::{DexEntry, LH_SIG, parse_cd_dex_entries};
use flate2::Compression;
use flate2::write::DeflateEncoder;
use std::fs;
use std::io::Write;
use std::path::PathBuf;
use std::sync::atomic::AtomicBool;

fn corpus_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../conformance/corpus")
}

#[test]
fn test_inflate_stored_and_deflated_from_corpus() {
    let c_dir = corpus_dir();

    // 1. Stored
    let stored_path = c_dir.join("fixture_stored.apk");
    if stored_path.exists() {
        let data = fs::read(&stored_path).unwrap();
        let entries = parse_cd_dex_entries(&data).unwrap();
        let inflated = inflate_entry(&data, &entries[0], None).unwrap().unwrap();
        assert_eq!(inflated.len() as u32, entries[0].uncomp_size);
        assert!(inflated.starts_with(b"dex\n"));
    }

    // 2. Deflated
    let deflated_path = c_dir.join("fixture_mutf8.apk");
    if deflated_path.exists() {
        let data = fs::read(&deflated_path).unwrap();
        let entries = parse_cd_dex_entries(&data).unwrap();
        let inflated = inflate_entry(&data, &entries[0], None).unwrap().unwrap();
        assert_eq!(inflated.len() as u32, entries[0].uncomp_size);
        assert!(inflated.starts_with(b"dex\n"));
    }
}

#[test]
fn test_inflate_cancel_token() {
    let c_dir = corpus_dir();
    let deflated_path = c_dir.join("fixture_mutf8.apk");
    if deflated_path.exists() {
        let data = fs::read(&deflated_path).unwrap();
        let entries = parse_cd_dex_entries(&data).unwrap();
        let cancel = AtomicBool::new(true); // already cancelled
        let res = inflate_entry(&data, &entries[0], Some(&cancel)).unwrap();
        assert_eq!(res, None);
    }
}

#[test]
fn test_inflate_synthetic_roundtrip_and_errors() {
    let payload = b"The quick brown fox jumps over the lazy dog. 0123456789";
    let mut encoder = DeflateEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(payload).unwrap();
    let compressed = encoder.finish().unwrap();

    let mut zip_buf = Vec::new();
    // Local header at offset 0
    zip_buf.extend_from_slice(&LH_SIG);
    zip_buf.extend_from_slice(&[0u8; 22]); // version, flags, method, time, crc, comp_size, uncomp_size
    let name = b"classes.dex";
    zip_buf.extend_from_slice(&(name.len() as u16).to_le_bytes()); // name_len
    zip_buf.extend_from_slice(&0u16.to_le_bytes()); // extra_len
    zip_buf.extend_from_slice(name);
    // Data
    zip_buf.extend_from_slice(&compressed);

    let entry = DexEntry {
        name: "classes.dex".to_string(),
        uncomp_size: payload.len() as u32,
        comp_size: compressed.len() as u32,
        local_header_off: 0,
        method: 8,
    };

    // 1. Success
    let decomp = inflate_entry(&zip_buf, &entry, None).unwrap().unwrap();
    assert_eq!(decomp, payload);

    // 2. Size mismatch
    let mut bad_size_entry = entry.clone();
    bad_size_entry.uncomp_size = payload.len() as u32 + 10;
    assert_eq!(
        inflate_entry(&zip_buf, &bad_size_entry, None),
        Err(AscError::SizeMismatch {
            expected: payload.len() as u32 + 10,
            got: payload.len(),
        })
    );

    // 3. Bad local header signature
    let mut bad_sig_entry = entry.clone();
    bad_sig_entry.local_header_off = 10;
    assert_eq!(
        inflate_entry(&zip_buf, &bad_sig_entry, None),
        Err(AscError::BadLocalHeaderSignature)
    );

    // 4. Corrupt deflate stream
    let mut corrupt_buf = zip_buf.clone();
    let data_start = 30 + name.len();
    corrupt_buf[data_start..data_start + 10].fill(0xff);
    assert!(matches!(
        inflate_entry(&corrupt_buf, &entry, None),
        Err(AscError::CorruptDeflateStream(_))
    ));
}

#[test]
fn test_inflate_corrupt_deflate_fixture() {
    let c_dir = corpus_dir();
    let corrupt_path = c_dir.join("fixture_corrupt_deflate.apk");
    if corrupt_path.exists() {
        let data = fs::read(&corrupt_path).unwrap();
        let entries = parse_cd_dex_entries(&data).unwrap();
        let entry = &entries[0];
        let lh_off = entry.local_header_off as usize;
        let data_off = lh_off + 30 + entry.name.len();
        let comp = &data[data_off..data_off + entry.comp_size as usize];
        let mut decomp = flate2::Decompress::new(false);
        let mut buf = [0u8; 200];
        let res = decomp.decompress(comp, &mut buf, flate2::FlushDecompress::None);
        println!(
            "decomp step 1: {:?}, in={}, out={}",
            res,
            decomp.total_in(),
            decomp.total_out()
        );
        let res2 = decomp.decompress(&[], &mut buf, flate2::FlushDecompress::Finish);
        println!(
            "decomp step 2: {:?}, in={}, out={}",
            res2,
            decomp.total_in(),
            decomp.total_out()
        );
    }
}
