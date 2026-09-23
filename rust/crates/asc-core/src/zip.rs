#![warn(clippy::arithmetic_side_effects)]

use crate::bytes::{record, u16_at, u32_at};
use crate::error::AscError;
use std::collections::HashSet;

pub const EOCD_SIG: [u8; 4] = [0x50, 0x4b, 0x05, 0x06];
pub const CD_SIG: [u8; 4] = [0x50, 0x4b, 0x01, 0x02];
pub const LH_SIG: [u8; 4] = [0x50, 0x4b, 0x03, 0x04];
const DEX_SUFFIX: &[u8] = b".dex";
const SLASH: u8 = b'/';
/// Size of the fixed part of a central directory record; the file name follows it.
const CD_HEADER_LEN: usize = 46;

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
                let (valid, rest) = remaining.split_at(e.valid_up_to());
                if let Ok(valid_prefix) = std::str::from_utf8(valid) {
                    s.push_str(valid_prefix);
                }
                let skip = e.error_len().unwrap_or(1);
                remaining = rest.get(skip..).unwrap_or_default();
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
    let search_start = data.len().saturating_sub(65536 + 22);
    let (_, window) = data.split_at(search_start);

    let pos = match window.windows(4).rposition(|w| w == EOCD_SIG) {
        Some(p) => search_start.checked_add(p).ok_or(AscError::EocdNotFound)?,
        None => return Err(AscError::EocdNotFound),
    };

    let eocd = record(data, pos, 22).ok_or(AscError::BadEocdHeader)?;
    let cd_size = u32_at(eocd, 12).ok_or(AscError::BadEocdHeader)? as usize;
    let cd_off = u32_at(eocd, 16).ok_or(AscError::BadEocdHeader)? as usize;

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
    let cd_end = cd_off
        .checked_add(eocd.cd_size)
        .ok_or(AscError::BadCentralDirectoryRange)?;
    if cd_off > data.len() || cd_end > data.len() {
        return Err(AscError::BadCentralDirectoryRange);
    }

    // Fast path: search for b"classes" in CD range with name deduplication
    let mut entries = Vec::new();
    let mut seen_names: HashSet<Vec<u8>> = HashSet::new();
    let mut search_pos = cd_off;

    while let Some(haystack) = data.get(search_pos..cd_end).filter(|h| h.len() >= 7) {
        let rel_pos = match haystack.windows(7).position(|w| w == b"classes") {
            Some(p) => p,
            None => break,
        };
        // Both are positions inside `data`, so saturation never engages.
        let match_pos = search_pos.saturating_add(rel_pos);
        search_pos = match_pos.saturating_add(7);
        let Some(header_off) = match_pos.checked_sub(CD_HEADER_LEN) else {
            continue;
        };

        if header_off < cd_off {
            continue;
        }
        // The record runs to the end of the CD; it must hold the fixed header.
        let Some(rec) = data
            .get(header_off..cd_end)
            .filter(|r| r.len() >= CD_HEADER_LEN)
        else {
            continue;
        };
        if !rec.starts_with(&CD_SIG) {
            continue;
        }

        let name_len = usize::from(cd_u16(rec, 28)?);
        let Some(name_bytes) = record(rec, CD_HEADER_LEN, name_len) else {
            continue;
        };
        if !is_top_level_dex(name_bytes) || seen_names.contains(name_bytes) {
            continue;
        }

        seen_names.insert(name_bytes.to_vec());
        entries.push(cd_entry(rec, name_bytes)?);
    }

    if !entries.is_empty() {
        return Ok(entries);
    }

    // Fallback: sequential scan of CD records without deduplication
    let mut ptr = cd_off;
    while let Some(rec) = data.get(ptr..cd_end).filter(|r| r.len() >= CD_HEADER_LEN) {
        if !rec.starts_with(&CD_SIG) {
            break;
        }

        let name_len = usize::from(cd_u16(rec, 28)?);
        let extra_len = usize::from(cd_u16(rec, 30)?);
        let comment_len = usize::from(cd_u16(rec, 32)?);

        let Some(name_bytes) = record(rec, CD_HEADER_LEN, name_len) else {
            break;
        };
        if is_top_level_dex(name_bytes) {
            entries.push(cd_entry(rec, name_bytes)?);
        }

        // An in-buffer offset plus three u16 lengths: saturation never engages.
        ptr = ptr
            .saturating_add(CD_HEADER_LEN)
            .saturating_add(name_len)
            .saturating_add(extra_len)
            .saturating_add(comment_len);
    }

    Ok(entries)
}

/// Whether a CD file name is a `.dex` file outside any directory.
fn is_top_level_dex(name_bytes: &[u8]) -> bool {
    name_bytes.ends_with(DEX_SUFFIX) && !name_bytes.contains(&SLASH)
}

/// Builds the entry for the CD record at the start of `rec`, named `name_bytes`.
fn cd_entry(rec: &[u8], name_bytes: &[u8]) -> Result<DexEntry, AscError> {
    let uncomp_size = cd_u32(rec, 24)?;
    let comp_size = cd_u32(rec, 20)?;
    let local_header_off = cd_u32(rec, 42)?;
    let method = cd_u16(rec, 10)?;
    Ok(DexEntry {
        name: decode_utf8_ignore(name_bytes),
        uncomp_size,
        comp_size,
        local_header_off,
        method,
    })
}

fn cd_u16(rec: &[u8], off: usize) -> Result<u16, AscError> {
    u16_at(rec, off).ok_or(AscError::BadCentralDirectoryRange)
}

fn cd_u32(rec: &[u8], off: usize) -> Result<u32, AscError> {
    u32_at(rec, off).ok_or(AscError::BadCentralDirectoryRange)
}
