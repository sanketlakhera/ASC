#![no_main]

use asc_core::inflate::inflate_entry;
use asc_core::zip::{DexEntry, parse_cd_dex_entries};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Path 1: the input is an APK; inflate every entry its central directory lists.
    if let Ok(entries) = parse_cd_dex_entries(data) {
        for entry in &entries {
            let _ = inflate_entry(data, entry, None);
        }
    }

    // Path 2: the first 15 bytes are a forged central-directory entry over the rest,
    // so local-header and size checks are reached without a valid EOCD.
    let Some((hdr, buf)) = data.split_first_chunk::<15>() else {
        return;
    };
    let u32_at = |i: usize| u32::from_le_bytes([hdr[i], hdr[i + 1], hdr[i + 2], hdr[i + 3]]);
    let entry = DexEntry {
        name: "classes.dex".to_string(),
        uncomp_size: u32_at(0),
        comp_size: u32_at(4),
        local_header_off: u32_at(8),
        method: match hdr[12] % 4 {
            0 => 0,
            1 | 2 => 8,
            _ => u16::from_le_bytes([hdr[13], hdr[14]]),
        },
    };
    let _ = inflate_entry(buf, &entry, None);
});
