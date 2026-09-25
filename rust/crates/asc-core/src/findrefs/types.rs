//! `TypeLocator` (`type_locator.py`): a type query is a string query over the
//! descriptors, mapped to the type ids that name the matched strings.
//!
//! The query is not normalised: `findrefs type com.poc.Main` works only because
//! `.` is a regex wildcard that also matches `/`.

use crate::dex::Dex;
use crate::error::AscError;
use crate::findrefs::index::Index;
use crate::findrefs::string::StringLocator;
use std::collections::BTreeSet;

pub struct TypeLocator {
    /// str_idx -> type ids naming it, ascending.
    map: Index,
}

impl TypeLocator {
    pub fn build(dex: &Dex<'_>) -> Result<Self, AscError> {
        let (off, size) = dex.header.types;
        let table = size
            .checked_mul(4)
            .and_then(|len| dex.buf.get(off..)?.get(..len))
            .ok_or(AscError::BadTypeIdsRange)?;
        let pairs = (0u32..)
            .zip(table.as_chunks::<4>().0)
            .map(|(type_idx, entry)| (u32::from_le_bytes(*entry), type_idx))
            .collect();
        Ok(Self {
            map: Index::build(pairs),
        })
    }

    /// The type ids of `str_idx`.
    pub fn types_of(&self, str_idx: u32) -> &[u32] {
        self.map.get(str_idx)
    }

    pub fn locate(
        &self,
        strings: &StringLocator,
        buf: &[u8],
        query: &[u16],
    ) -> Result<BTreeSet<u32>, AscError> {
        let mut located = BTreeSet::new();
        if query.is_empty() {
            return Ok(located);
        }
        for str_idx in strings.locate(buf, query)? {
            located.extend(self.types_of(str_idx));
        }
        Ok(located)
    }

    /// `(str_idx, type ids)` sorted by str_idx, for the stage dump.
    pub fn entries(&self) -> Vec<(u32, &[u32])> {
        self.map.entries()
    }
}
