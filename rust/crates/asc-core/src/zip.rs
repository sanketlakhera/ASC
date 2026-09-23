use crate::error::AscError;
use std::collections::HashSet;

pub const EOCD_SIG: [u8; 4] = [0x50, 0x4b, 0x05, 0x06];
pub const CD_SIG: [u8; 4] = [0x50, 0x4b, 0x01, 0x02];
pub const LH_SIG: [u8; 4] = [0x50, 0x4b, 0x03, 0x04];
const DEX_SUFFIX: &[u8] = b".dex";
const SLASH: u8 = b'/';

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DexEntry {
    pub name: String,
    pub uncomp_size: u32,
    pub comp_size: u32,
    pub local_header_off: u32,
    pub method: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Eocd {
    pub offset: usize,
    pub cd_size: usize,
    pub cd_off: usize,
}

/// Decodes byte slice to String using UTF-8 with errors="ignore" behavior,
/// omitting any invalid byte sequences without replacing them.
pub fn decode_utf8_ignore(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len());
    let mut remaining = bytes;
    while !remaining.is_empty() {
        match std::str::from_utf8(remaining) {
            Ok(valid) => {
                s.push_str(valid);
                break;
            }
            Err(e) => {
                let valid_up_to = e.valid_up_to();
                if let Ok(valid_prefix) = std::str::from_utf8(&remaining[..valid_up_to]) {
                    s.push_str(valid_prefix);
                }
                let skip = e.error_len().unwrap_or(1);
                remaining = &remaining[valid_up_to + skip..];
            }
        }
    }
    s
}

/// Locates the EOCD (End of Central Directory) record in an APK / ZIP buffer.
///
/// Searches backward from the end in the last min(len, 65536 + 22) bytes.
pub fn find_eocd(data: &[u8]) -> Result<Eocd, AscError> {
    if data.len() < 22 {
        return Err(AscError::EocdNotFound);
    }
    let search_window = std::cmp::min(data.len(), 65536 + 22);
    let search_start = data.len() - search_window;
    let window = &data[search_start..];

    let pos = match window.windows(4).rposition(|w| w == EOCD_SIG) {
        Some(p) => search_start + p,
        None => return Err(AscError::EocdNotFound),
    };

    if pos + 22 > data.len() {
        return Err(AscError::BadEocdHeader);
    }

    let cd_size = u32::from_le_bytes(
        data.get(pos + 12..pos + 16)
            .ok_or(AscError::BadEocdHeader)?
            .try_into()
            .unwrap(),
    ) as usize;

    let cd_off = u32::from_le_bytes(
        data.get(pos + 16..pos + 20)
            .ok_or(AscError::BadEocdHeader)?
            .try_into()
            .unwrap(),
    ) as usize;

    let cd_end = cd_off
        .checked_add(cd_size)
        .ok_or(AscError::BadCentralDirectoryRange)?;
    if cd_off > data.len() || cd_end > data.len() {
        return Err(AscError::BadCentralDirectoryRange);
    }

    Ok(Eocd {
        offset: pos,
        cd_size,
        cd_off,
    })
}

/// Parses DEX entries from the central directory of an APK.
///
/// First attempts a fast path searching for `classes` with deduplication.
/// If no entries are found, falls back to a sequential scan without deduplication.
pub fn parse_cd_dex_entries(data: &[u8]) -> Result<Vec<DexEntry>, AscError> {
    let eocd = find_eocd(data)?;
    parse_cd_dex_entries_with_eocd(data, &eocd)
}

/// Parses DEX entries given a pre-located EOCD.
pub fn parse_cd_dex_entries_with_eocd(data: &[u8], eocd: &Eocd) -> Result<Vec<DexEntry>, AscError> {
    let cd_off = eocd.cd_off;
    let cd_end = cd_off + eocd.cd_size;
    if cd_off > data.len() || cd_end > data.len() {
        return Err(AscError::BadCentralDirectoryRange);
    }

    // Fast path: search for b"classes" in CD range with name deduplication
    let mut entries = Vec::new();
    let mut seen_names: HashSet<Vec<u8>> = HashSet::new();
    let mut search_pos = cd_off;

    while search_pos + 7 <= cd_end {
        let haystack = &data[search_pos..cd_end];
        let rel_pos = match haystack.windows(7).position(|w| w == b"classes") {
            Some(p) => p,
            None => break,
        };
        let match_pos = search_pos + rel_pos;
        if match_pos < 46 {
            search_pos = match_pos + 7;
            continue;
        }
        let header_off = match_pos - 46;
        search_pos = match_pos + 7;

        if header_off < cd_off || header_off + 46 > cd_end {
            continue;
        }
        if data.get(header_off..header_off + 4) != Some(&CD_SIG) {
            continue;
        }

        let name_len = u16::from_le_bytes(
            data.get(header_off + 28..header_off + 30)
                .ok_or(AscError::BadCentralDirectoryRange)?
                .try_into()
                .unwrap(),
        ) as usize;

        let name_start = match_pos;
        let name_end = name_start + name_len;
        if name_end > cd_end {
            continue;
        }

        let name_bytes = &data[name_start..name_end];
        if !name_bytes.ends_with(DEX_SUFFIX)
            || name_bytes.contains(&SLASH)
            || seen_names.contains(name_bytes)
        {
            continue;
        }

        seen_names.insert(name_bytes.to_vec());

        let uncomp_size = u32::from_le_bytes(
            data.get(header_off + 24..header_off + 28)
                .ok_or(AscError::BadCentralDirectoryRange)?
                .try_into()
                .unwrap(),
        );
        let comp_size = u32::from_le_bytes(
            data.get(header_off + 20..header_off + 24)
                .ok_or(AscError::BadCentralDirectoryRange)?
                .try_into()
                .unwrap(),
        );
        let local_header_off = u32::from_le_bytes(
            data.get(header_off + 42..header_off + 46)
                .ok_or(AscError::BadCentralDirectoryRange)?
                .try_into()
                .unwrap(),
        );
        let method = u16::from_le_bytes(
            data.get(header_off + 10..header_off + 12)
                .ok_or(AscError::BadCentralDirectoryRange)?
                .try_into()
                .unwrap(),
        );

        entries.push(DexEntry {
            name: decode_utf8_ignore(name_bytes),
            uncomp_size,
            comp_size,
            local_header_off,
            method,
        });
    }

    if !entries.is_empty() {
        return Ok(entries);
    }

    // Fallback: sequential scan of CD records without deduplication
    let mut ptr = cd_off;
    while ptr + 46 <= cd_end {
        if data.get(ptr..ptr + 4) != Some(&CD_SIG) {
            break;
        }

        let name_len = u16::from_le_bytes(
            data.get(ptr + 28..ptr + 30)
                .ok_or(AscError::BadCentralDirectoryRange)?
                .try_into()
                .unwrap(),
        ) as usize;
        let extra_len = u16::from_le_bytes(
            data.get(ptr + 30..ptr + 32)
                .ok_or(AscError::BadCentralDirectoryRange)?
                .try_into()
                .unwrap(),
        ) as usize;
        let comment_len = u16::from_le_bytes(
            data.get(ptr + 32..ptr + 34)
                .ok_or(AscError::BadCentralDirectoryRange)?
                .try_into()
                .unwrap(),
        ) as usize;

        let name_start = ptr + 46;
        let name_end = name_start + name_len;
        if name_end > cd_end {
            break;
        }

        let name_bytes = &data[name_start..name_end];
        if name_bytes.ends_with(DEX_SUFFIX) && !name_bytes.contains(&SLASH) {
            let uncomp_size = u32::from_le_bytes(
                data.get(ptr + 24..ptr + 28)
                    .ok_or(AscError::BadCentralDirectoryRange)?
                    .try_into()
                    .unwrap(),
            );
            let comp_size = u32::from_le_bytes(
                data.get(ptr + 20..ptr + 24)
                    .ok_or(AscError::BadCentralDirectoryRange)?
                    .try_into()
                    .unwrap(),
            );
            let local_header_off = u32::from_le_bytes(
                data.get(ptr + 42..ptr + 46)
                    .ok_or(AscError::BadCentralDirectoryRange)?
                    .try_into()
                    .unwrap(),
            );
            let method = u16::from_le_bytes(
                data.get(ptr + 10..ptr + 12)
                    .ok_or(AscError::BadCentralDirectoryRange)?
                    .try_into()
                    .unwrap(),
            );

            entries.push(DexEntry {
                name: decode_utf8_ignore(name_bytes),
                uncomp_size,
                comp_size,
                local_header_off,
                method,
            });
        }

        ptr = name_end + extra_len + comment_len;
    }

    Ok(entries)
}
