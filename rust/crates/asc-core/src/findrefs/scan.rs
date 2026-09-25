//! `CodeItemScanner` (`code_item_scan.py`): every byte position of the code
//! region whose byte is an opcode of the query's kind and whose index operand
//! (two bytes after it) is a located id. Hits are not instruction-aligned and
//! the region includes code_item headers and whatever lies between bodies; the
//! verifier rejects the false ones.
//!
//! Python has two implementations (a regex prefilter for the string opcodes, a
//! translate-and-bigint mask for the rest). Both find the same set: an opcode
//! at `p` with `p + 2 + width <= end` and the operand in the id set.
//!
//! Not scanned, as in Python: const-method-handle, const-method-type,
//! invoke-custom and the proto operand of invoke-polymorphic.

use std::collections::BTreeSet;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RefKind {
    String,
    Type,
    Field,
    Method,
}

impl RefKind {
    /// Operand width of `op` in bytes, or 0 when `op` is not scanned for this kind.
    fn width(self, op: u8) -> usize {
        match (self, op) {
            (Self::String, 0x1a) => 2,
            // const-string/jumbo
            (Self::String, 0x1b) => 4,
            (Self::Type, 0x1c | 0x1f | 0x20 | 0x22 | 0x23 | 0x24 | 0x25) => 2,
            (Self::Field, 0x52..=0x6d) => 2,
            (Self::Method, 0x6e..=0x72 | 0x74..=0x78 | 0xfa | 0xfb) => 2,
            _ => 0,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::String => "string",
            Self::Type => "type",
            Self::Field => "field",
            Self::Method => "method",
        }
    }
}

/// Hit offsets (absolute, ascending) and the id each one references.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Scan {
    pub offsets: Vec<usize>,
    pub marks: Vec<u32>,
}

/// Scans `buf[start..min(end, len)]`; the bucket-aligned end can pass the
/// buffer end by up to 15 bytes.
pub fn scan(buf: &[u8], (start, end): (usize, usize), kind: RefKind, ids: &BTreeSet<u32>) -> Scan {
    let mut out = Scan::default();
    let end = end.min(buf.len());
    let Some(region) = buf.get(start..end) else {
        return out;
    };
    let Some(&max_id) = ids.last() else {
        return out;
    };
    let mut wanted = vec![0u64; (max_id as usize >> 6).saturating_add(1)];
    for &id in ids {
        if let Some(word) = wanted.get_mut(id as usize >> 6) {
            *word |= 1 << (id & 63);
        }
    }
    let has = |id: u32| {
        wanted
            .get(id as usize >> 6)
            .is_some_and(|w| w & (1 << (id & 63)) != 0)
    };
    let mut table = [0u8; 256];
    for (op, slot) in (0u8..=255).zip(table.iter_mut()) {
        *slot = kind.width(op) as u8;
    }
    let mut check = |p: usize, width: u8| {
        let Some(operand) = p
            .checked_add(2)
            .and_then(|at| region.get(at..at.checked_add(usize::from(width))?))
        else {
            return;
        };
        let id = match *operand {
            [a, b] => u32::from(u16::from_le_bytes([a, b])),
            [a, b, c, d] => u32::from_le_bytes([a, b, c, d]),
            _ => return,
        };
        if has(id) {
            out.offsets.push(start.saturating_add(p));
            out.marks.push(id);
        }
    };
    if kind == RefKind::String {
        // two opcodes: let memchr find them instead of testing every byte
        for p in memchr::memchr2_iter(0x1a, 0x1b, region) {
            let width = if region.get(p) == Some(&0x1a) { 2 } else { 4 };
            check(p, width);
        }
    } else {
        for (p, &op) in region.iter().enumerate() {
            let width = table.get(usize::from(op)).copied().unwrap_or(0);
            if width != 0 {
                check(p, width);
            }
        }
    }
    out
}
