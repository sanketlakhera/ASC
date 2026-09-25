//! `AscHandler._format_method` / `_format_matched_name`: names through tinydex
//! (`DexMethod`, `DexField`, `get_type`, `get_string`), so their errors are
//! tinydex's. Names stay UTF-16 until the output edge (`to_output`).

use crate::bytes::{u16_at, u32_at};
use crate::dex::Dex;
use crate::error::AscError;
use crate::findrefs::scan::RefKind;

/// tinydex `DexMethod(dex, idx)` / `DexField(dex, idx)`: the `(class_idx,
/// name_idx)` of an id entry. Only the buffer bounds it, not the count, and
/// method ids from class_data can be any 35-bit sum.
fn id_entry(
    dex: &Dex<'_>,
    table_off: usize,
    idx: u64,
    err: AscError,
) -> Result<(u16, u32), AscError> {
    let at = usize::try_from(idx)
        .ok()
        .and_then(|i| i.checked_mul(8)?.checked_add(table_off))
        .filter(|at| at.checked_add(8).is_some_and(|end| end <= dex.buf.len()));
    let Some(at) = at else { return Err(err) };
    match (
        u16_at(dex.buf, at),
        at.checked_add(4).and_then(|n| u32_at(dex.buf, n)),
    ) {
        (Some(class_idx), Some(name_idx)) => Ok((class_idx, name_idx)),
        _ => Err(err),
    }
}

/// `f"{cls.fullname}->{name}"`, class first.
fn member(dex: &Dex<'_>, table_off: usize, idx: u64, err: AscError) -> Result<Vec<u16>, AscError> {
    let (class_idx, name_idx) = id_entry(dex, table_off, idx, err)?;
    let (_, class) = dex.get_type(usize::from(class_idx))?;
    let name = dex.get_string(name_idx as usize)?;
    let mut out = class.descriptor.0;
    out.extend("->".encode_utf16());
    out.extend_from_slice(&name);
    Ok(out)
}

/// `_format_method(dex, midx)`.
pub fn method_name(dex: &Dex<'_>, midx: u64) -> Result<Vec<u16>, AscError> {
    member(dex, dex.header.methods.0, midx, AscError::BadMethodIdsRange)
}

/// `_format_matched_name(dex, kind, idx)`.
pub fn matched_name(dex: &Dex<'_>, kind: RefKind, idx: u32) -> Result<Vec<u16>, AscError> {
    match kind {
        RefKind::String => Ok(dex.get_string(idx as usize)?.0),
        RefKind::Type => Ok(dex.get_type(idx as usize)?.1.descriptor.0),
        RefKind::Method => method_name(dex, u64::from(idx)),
        RefKind::Field => member(
            dex,
            dex.header.fields.0,
            u64::from(idx),
            AscError::BadFieldIdsRange,
        ),
    }
}

/// Text as Python writes a str with `errors="replace"`: valid surrogate pairs
/// become their character, a lone surrogate becomes `?`.
pub fn to_output(units: &[u16]) -> String {
    char::decode_utf16(units.iter().copied())
        .map(|r| r.unwrap_or('?'))
        .collect()
}
