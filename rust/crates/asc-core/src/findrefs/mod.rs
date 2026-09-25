//! findrefs: code references to a string, type, method or field in one
//! logical DEX (`FindRefManager.find_ref` + `AscHandler.findrefs`).
//!
//! Locators are built lazily and in a fixed order, which decides the error a
//! corrupt DEX reports:
//!
//! | query  | builds, in order                         |
//! |--------|------------------------------------------|
//! | string | string map                               |
//! | type   | string map, type map                     |
//! | method | string map, type map, method map         |
//! | field  | string map, type map, field map          |
//!
//! then `locate`. An empty result stops there: the instruction map is never
//! built, so a corrupt code_item goes unnoticed when nothing matched.

pub mod format;
mod index;
pub mod insn;
pub mod member;
pub mod pattern;
pub mod scan;
pub mod string;
pub mod types;
pub mod verify;

use crate::dex::Dex;
use crate::error::AscError;
use insn::{InsnLocator, Owner};
use member::{MemberKind, MemberLocator, MemberQuery};
use scan::{RefKind, Scan};
use std::collections::{BTreeMap, BTreeSet};
use string::StringLocator;
use types::TypeLocator;

/// A findrefs query, text as Python `str` (UTF-16 units, lone surrogates kept).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Query {
    String(Vec<u16>),
    Type(Vec<u16>),
    Method(MemberQuery),
    Field(MemberQuery),
}

impl Query {
    pub fn kind(&self) -> RefKind {
        match self {
            Self::String(_) => RefKind::String,
            Self::Type(_) => RefKind::Type,
            Self::Method(_) => RefKind::Method,
            Self::Field(_) => RefKind::Field,
        }
    }
}

/// What `find_ref` computed for one query.
#[derive(Debug, Clone, Default)]
pub struct Refs {
    pub located: BTreeSet<u32>,
    /// Scan hits, and for each hit its verified owner (`None` when the
    /// instruction walk fails). Absent when nothing was located.
    pub hits: Option<(Scan, Vec<Option<Owner>>)>,
}

pub struct FindRefs<'a> {
    pub dex: Dex<'a>,
    strings: Option<StringLocator>,
    types: Option<TypeLocator>,
    methods: Option<MemberLocator>,
    fields: Option<MemberLocator>,
    insn: Option<InsnLocator>,
}

impl<'a> FindRefs<'a> {
    /// `DEX.parse`: header errors come first.
    pub fn new(buf: &'a [u8]) -> Result<Self, AscError> {
        Ok(Self {
            dex: Dex::new(buf)?,
            strings: None,
            types: None,
            methods: None,
            fields: None,
            insn: None,
        })
    }

    fn build_strings(&mut self) -> Result<(), AscError> {
        if self.strings.is_none() {
            self.strings = Some(StringLocator::build(&self.dex)?);
        }
        Ok(())
    }

    fn build_types(&mut self) -> Result<(), AscError> {
        self.build_strings()?;
        if self.types.is_none() {
            self.types = Some(TypeLocator::build(&self.dex)?);
        }
        Ok(())
    }

    fn build_members(&mut self, kind: MemberKind) -> Result<(), AscError> {
        self.build_types()?;
        let slot = match kind {
            MemberKind::Method => &mut self.methods,
            MemberKind::Field => &mut self.fields,
        };
        if slot.is_none() {
            *slot = Some(MemberLocator::build(&self.dex, kind)?);
        }
        Ok(())
    }

    /// The located ids of a query, building its locators first.
    pub fn locate(&mut self, query: &Query) -> Result<BTreeSet<u32>, AscError> {
        match query {
            Query::String(q) => {
                self.build_strings()?;
                let strings = self.strings.as_ref().ok_or(AscError::BadStringIdsRange)?;
                strings.locate(self.dex.buf, q)
            }
            Query::Type(q) => {
                self.build_types()?;
                let (Some(strings), Some(types)) = (&self.strings, &self.types) else {
                    return Err(AscError::BadTypeIdsRange);
                };
                types.locate(strings, self.dex.buf, q)
            }
            Query::Method(q) | Query::Field(q) => {
                let kind = if matches!(query, Query::Method(_)) {
                    MemberKind::Method
                } else {
                    MemberKind::Field
                };
                self.build_members(kind)?;
                let members = match kind {
                    MemberKind::Method => &self.methods,
                    MemberKind::Field => &self.fields,
                };
                let (Some(strings), Some(types), Some(members)) =
                    (&self.strings, &self.types, members)
                else {
                    return Err(kind.range_error());
                };
                members.locate(&self.dex, strings, types, q)
            }
        }
    }

    /// The instruction map, built on first use.
    pub fn insn(&mut self) -> Result<&InsnLocator, AscError> {
        if self.insn.is_none() {
            self.insn = Some(InsnLocator::parse(&self.dex)?);
        }
        self.insn.as_ref().ok_or(AscError::BadCodeItemOffset)
    }

    /// Scan the code region for references to `ids` and verify every hit.
    pub fn scan(
        &mut self,
        kind: RefKind,
        ids: &BTreeSet<u32>,
    ) -> Result<(Scan, Vec<Option<Owner>>), AscError> {
        let buf = self.dex.buf;
        let insn = self.insn()?;
        let hits = scan::scan(buf, insn.code_range(), kind, ids);
        let owners = insn.verify(buf, &hits.offsets);
        Ok((hits, owners))
    }

    /// `FindRefManager.find_ref(query, mark=True)`.
    pub fn find_ref(&mut self, query: &Query) -> Result<Refs, AscError> {
        let located = self.locate(query)?;
        if located.is_empty() {
            return Ok(Refs {
                located,
                hits: None,
            });
        }
        let hits = self.scan(query.kind(), &located)?;
        Ok(Refs {
            located,
            hits: Some(hits),
        })
    }
}

/// `AscHandler.findrefs(dex_name, dex_buf, kind, find)`: one line per
/// referencing method, ascending by method idx, as UTF-16 units:
/// `{dex_name} | {Lcls;}->{name} | matched=({a}; {b})`.
pub fn findrefs(dex_name: &str, buf: &[u8], query: &Query) -> Result<Vec<Vec<u16>>, AscError> {
    let mut refs = FindRefs::new(buf)?;
    let found = refs.find_ref(query)?;
    let Some((scan, owners)) = found.hits else {
        return Ok(Vec::new());
    };
    let mut grouped: BTreeMap<u64, BTreeSet<u32>> = BTreeMap::new();
    for (owner, &mark) in owners.iter().zip(&scan.marks) {
        let Some(owner) = owner else { continue };
        for &mid in owner.mids() {
            grouped.entry(mid).or_default().insert(mark);
        }
    }
    let kind = query.kind();
    let name: Vec<u16> = dex_name.encode_utf16().collect();
    let mut lines = Vec::with_capacity(grouped.len());
    for (mid, idxs) in grouped {
        // The matched names are formatted before the method, as in the f-string.
        let mut matched = Vec::new();
        for (i, &idx) in idxs.iter().enumerate() {
            if i > 0 {
                matched.extend("; ".encode_utf16());
            }
            matched.extend(format::matched_name(&refs.dex, kind, idx)?);
        }
        let method = format::method_name(&refs.dex, mid)?;
        let mut line = name.clone();
        line.extend(" | ".encode_utf16());
        line.extend(method);
        line.extend(" | matched=(".encode_utf16());
        line.extend(matched);
        line.push(u16::from(b')'));
        lines.push(line);
    }
    Ok(lines)
}
