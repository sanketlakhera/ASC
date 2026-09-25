//! `MethodLocator` and `FieldLocator` (`method_locator.py`, `field_locator.py`):
//! one implementation, the two differ only in their table and its error.
//!
//! The name is a regex in two of the three modes and a literal in the third:
//! with no class or a fuzzy class it is a string query; with a precise class it
//! is a substring search (`str.find`) over the decoded member names.

use crate::bytes::u32_at;
use crate::dex::Dex;
use crate::error::AscError;
use crate::findrefs::index::Index;
use crate::findrefs::string::StringLocator;
use crate::findrefs::types::TypeLocator;
use crate::mutf8::encode_mutf8;
use std::cmp::Ordering;
use std::collections::BTreeSet;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemberKind {
    Method,
    Field,
}

impl MemberKind {
    fn table(self, dex: &Dex<'_>) -> (usize, usize) {
        match self {
            Self::Method => dex.header.methods,
            Self::Field => dex.header.fields,
        }
    }
    pub fn range_error(self) -> AscError {
        match self {
            Self::Method => AscError::BadMethodIdsRange,
            Self::Field => AscError::BadFieldIdsRange,
        }
    }
}

/// A member query as the CLI builds it: `{"class": None | [class, precise],
/// kind: name | None}`. Empty strings mean "not given".
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MemberQuery {
    /// `(class, precise)`.
    pub class: Option<(Vec<u16>, bool)>,
    pub name: Option<Vec<u16>>,
}

pub struct MemberLocator {
    kind: MemberKind,
    /// class type idx -> member ids, ascending.
    by_class: Index,
    /// name str idx -> member ids, ascending.
    by_name: Index,
}

impl MemberLocator {
    pub fn build(dex: &Dex<'_>, kind: MemberKind) -> Result<Self, AscError> {
        let (off, size) = kind.table(dex);
        let table = size
            .checked_mul(8)
            .and_then(|len| dex.buf.get(off..)?.get(..len))
            .ok_or(kind.range_error())?;
        let entries = table.as_chunks::<8>().0;
        let mut by_class = Vec::with_capacity(entries.len());
        let mut by_name = Vec::with_capacity(entries.len());
        for (idx, entry) in (0u32..).zip(entries) {
            let [c0, c1, _, _, n0, n1, n2, n3] = *entry;
            by_class.push((u32::from(u16::from_le_bytes([c0, c1])), idx));
            by_name.push((u32::from_le_bytes([n0, n1, n2, n3]), idx));
        }
        Ok(Self {
            kind,
            by_class: Index::build(by_class),
            by_name: Index::build(by_name),
        })
    }

    pub fn locate(
        &self,
        dex: &Dex<'_>,
        strings: &StringLocator,
        types: &TypeLocator,
        query: &MemberQuery,
    ) -> Result<BTreeSet<u32>, AscError> {
        let class = query.class.as_ref().filter(|(c, _)| !c.is_empty());
        let name = query.name.as_deref().filter(|n| !n.is_empty());
        let empty = BTreeSet::new();
        let Some((class, precise)) = class else {
            let Some(name) = name else {
                return Ok(empty);
            };
            let mut located = BTreeSet::new();
            for name_idx in strings.locate(dex.buf, name)? {
                located.extend(self.by_name.get(name_idx));
            }
            return Ok(located);
        };

        let in_class: BTreeSet<u32> = if *precise {
            let Some(type_idx) = find_type_idx_precisely(dex, class)? else {
                return Ok(empty);
            };
            // A type idx past u16 names no member: its list is empty.
            self.by_class.get(type_idx).iter().copied().collect()
        } else {
            let mut ids = BTreeSet::new();
            for type_idx in types.locate(strings, dex.buf, class)? {
                ids.extend(self.by_class.get(type_idx));
            }
            if ids.is_empty() {
                return Ok(empty);
            }
            ids
        };
        let Some(name) = name else {
            return Ok(in_class);
        };
        if *precise {
            // str.find on the decoded names, in ascending id order.
            let needle = code_points(name);
            let mut located = BTreeSet::new();
            for id in in_class {
                let name_idx = self.member_name_idx(dex, id)?;
                let member_name = dex.get_string(name_idx as usize)?;
                if contains(&code_points(&member_name), &needle) {
                    located.insert(id);
                }
            }
            return Ok(located);
        }
        let mut located = BTreeSet::new();
        for name_idx in strings.locate(dex.buf, name)? {
            located.extend(
                self.by_name
                    .get(name_idx)
                    .iter()
                    .filter(|m| in_class.contains(m)),
            );
        }
        Ok(located)
    }

    /// name_idx of member `id` (always inside the table checked by `build`).
    fn member_name_idx(&self, dex: &Dex<'_>, id: u32) -> Result<u32, AscError> {
        let (off, _) = self.kind.table(dex);
        (id as usize)
            .checked_mul(8)
            .and_then(|rel| rel.checked_add(off)?.checked_add(4))
            .and_then(|at| u32_at(dex.buf, at))
            .ok_or(self.kind.range_error())
    }

    /// `(key, ids)` of the class and name maps sorted by key, for the stage dump.
    pub fn class_entries(&self) -> Vec<(u32, &[u32])> {
        self.by_class.entries()
    }

    pub fn name_entries(&self) -> Vec<(u32, &[u32])> {
        self.by_name.entries()
    }
}

/// `_find_type_idx_precisely`: a binary search of type_ids by descriptor bytes
/// through tinydex's `get_string_bytes`, with Python's inclusive bounds and
/// `(left + right) >> 1`, so the same strings are probed and the same error
/// fires first.
pub fn find_type_idx_precisely(dex: &Dex<'_>, class: &[u16]) -> Result<Option<u32>, AscError> {
    let (off, size) = dex.header.types;
    let in_range = size
        .checked_mul(4)
        .and_then(|len| off.checked_add(len))
        .is_some_and(|end| end <= dex.buf.len());
    if !in_range {
        return Err(AscError::BadTypeIdsRange);
    }
    let target = encode_mutf8(class);
    let (mut left, mut right) = (
        0i64,
        i64::try_from(size).unwrap_or(i64::MAX).saturating_sub(1),
    );
    while left <= right {
        let mid = left.midpoint(right);
        let desc_idx = usize::try_from(mid)
            .ok()
            .and_then(|m| m.checked_mul(4)?.checked_add(off))
            .and_then(|at| u32_at(dex.buf, at))
            .ok_or(AscError::BadTypeIdsRange)?;
        match dex
            .get_string_bytes(desc_idx as usize)?
            .cmp(target.as_slice())
        {
            Ordering::Equal => return Ok(u32::try_from(mid).ok()),
            Ordering::Less => left = mid.saturating_add(1),
            Ordering::Greater => right = mid.saturating_sub(1),
        }
    }
    Ok(None)
}

/// The code points of a UTF-16 string as Python's `str` holds them: valid pairs
/// combine, lone surrogates stay themselves. `str.find` compares these.
pub fn code_points(units: &[u16]) -> Vec<u32> {
    char::decode_utf16(units.iter().copied())
        .map(|r| r.map_or_else(|e| u32::from(e.unpaired_surrogate()), u32::from))
        .collect()
}

fn contains(haystack: &[u32], needle: &[u32]) -> bool {
    needle.is_empty() || haystack.windows(needle.len()).any(|w| w == needle)
}
