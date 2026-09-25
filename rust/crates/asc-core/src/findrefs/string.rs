//! `StringLocator` (`string_locator.py`): a string query is one bytes regex over
//! the whole string_data region, not a per-string match.

use crate::bytes::u32_at;
use crate::dex::Dex;
use crate::error::AscError;
use crate::findrefs::pattern;
use crate::leb128::uleb128_len;
use crate::mutf8::encode_mutf8;
use std::collections::BTreeSet;

pub struct StringLocator {
    /// string_data_off of every string, ascending.
    starts: Vec<u32>,
    /// String idx at each position of `starts`, or `None` when `starts` is the
    /// string_ids table itself (already in ascending order).
    order: Option<Vec<u32>>,
    data_start: usize,
    data_end: usize,
    entries: usize,
}

impl StringLocator {
    /// `_build_map`, with its checks in Python's order.
    pub fn build(dex: &Dex<'_>) -> Result<Self, AscError> {
        let buf = dex.buf;
        let (ids_off, size) = dex.header.strings;
        let mut locator = Self {
            starts: Vec::new(),
            order: None,
            data_start: 0,
            data_end: 0,
            entries: size,
        };
        if size == 0 {
            return Ok(locator);
        }
        let table = size
            .checked_mul(4)
            .and_then(|len| buf.get(ids_off..)?.get(..len))
            .ok_or(AscError::BadStringIdsRange)?;
        let offsets: Vec<u32> = table
            .as_chunks::<4>()
            .0
            .iter()
            .map(|b| u32::from_le_bytes(*b))
            .collect();
        let mut sorted = offsets.clone();
        sorted.sort_unstable();
        let (Some(&lowest), Some(&highest)) = (sorted.first(), sorted.last()) else {
            return Ok(locator);
        };
        if highest as usize >= buf.len() {
            return Err(AscError::BadStringDataOffset);
        }
        // d8 and dx lay string_data out in string_ids order, so the table is
        // usually its own sorted form. Otherwise sort the indices by offset; the
        // sort is stable, so among equal offsets the highest idx comes last,
        // which is the one the search lands on.
        if sorted != offsets {
            let mut order: Vec<u32> = (0..size).filter_map(|i| u32::try_from(i).ok()).collect();
            order.sort_by_key(|&i| offsets.get(i as usize).copied().unwrap_or(u32::MAX));
            locator.order = Some(order);
        }
        locator.starts = sorted;
        // The region runs from the lowest string_data_item to the terminator
        // of the highest one.
        let highest = highest as usize;
        let prefix = uleb128_len(buf, highest)?;
        let data = highest
            .checked_add(prefix)
            .ok_or(AscError::UnterminatedStringDataItem)?;
        let nul = buf
            .get(data..)
            .and_then(|rest| memchr::memchr(0, rest))
            .ok_or(AscError::UnterminatedStringDataItem)?;
        locator.data_start = lowest as usize;
        locator.data_end = data.saturating_add(nul).saturating_add(1);
        Ok(locator)
    }

    /// `[strdata_start, strdata_end)`.
    pub fn region(&self) -> (usize, usize) {
        (self.data_start, self.data_end)
    }

    /// Number of string_ids entries.
    pub fn entries(&self) -> usize {
        self.entries
    }

    /// `locate`: the ids of the strings the pattern matches. The query is a
    /// Python str as UTF-16 units; it is MUTF-8 encoded before compiling.
    ///
    /// A match belongs to the string holding the first NUL at or after its end:
    /// the string with the greatest string_data_off not above that NUL. A match
    /// that consumed the final terminator has no such NUL and belongs to none.
    pub fn locate(&self, buf: &[u8], query: &[u16]) -> Result<BTreeSet<u32>, AscError> {
        let mut located = BTreeSet::new();
        if query.is_empty() {
            return Ok(located);
        }
        let regex = pattern::compile(&encode_mutf8(query))?;
        let Some(region) = buf.get(self.data_start..self.data_end) else {
            return Ok(located);
        };
        // Match ends ascend, so the NUL found for one match is also the first
        // NUL for every later match ending at or before it: one long string
        // with many matches is scanned once, not once per match.
        let mut last_nul: Option<usize> = None;
        for m in regex.find_iter(region) {
            let nul = match last_nul {
                Some(n) if n >= m.end() => n,
                _ => {
                    let Some(n) = region
                        .get(m.end()..)
                        .and_then(|rest| memchr::memchr(0, rest))
                        .map(|off| m.end().saturating_add(off))
                    else {
                        // no NUL after this end, so none after any later one
                        break;
                    };
                    last_nul = Some(n);
                    n
                }
            };
            located.insert(self.owner(self.data_start.saturating_add(nul)));
        }
        Ok(located)
    }

    /// The string whose data holds the byte at `at` (`at >= data_start`).
    fn owner(&self, at: usize) -> u32 {
        let pos = self
            .starts
            .partition_point(|&s| s as usize <= at)
            .saturating_sub(1);
        match &self.order {
            None => u32::try_from(pos).unwrap_or(u32::MAX),
            Some(order) => order.get(pos).copied().unwrap_or(u32::MAX),
        }
    }

    /// The `(string_data_off, idx)` pairs sorted by offset then idx, for the
    /// stage dump.
    pub fn table(dex: &Dex<'_>) -> Vec<(u32, u32)> {
        let (off, size) = dex.header.strings;
        let mut pairs: Vec<(u32, u32)> = (0..size)
            .map_while(|i| {
                let entry = off.checked_add(i.checked_mul(4)?)?;
                Some((u32_at(dex.buf, entry)?, u32::try_from(i).ok()?))
            })
            .collect();
        pairs.sort_unstable();
        pairs
    }
}
