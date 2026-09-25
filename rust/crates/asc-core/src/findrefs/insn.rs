//! `InsnLocator` (`insn_locator.py`): maps an instruction offset to the method
//! whose code holds it, through a table of 16-byte buckets filled from
//! class_data, then verifies each hit by walking instructions from the method
//! start (or from the method's last verified hit) up to it.

use crate::bytes::{u16_at, u32_at};
use crate::dex::Dex;
use crate::error::AscError;
use crate::findrefs::verify::walk_reaches;
use crate::leb128::{read_uleb128, uleb128_len};
use std::collections::HashMap;

/// What owns a bucket: one method, or several whose code shares the bucket
/// where the later one starts (R8 deduplicates identical bodies).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Owner {
    One(u64),
    Many(Vec<u64>),
}

impl Owner {
    pub fn mids(&self) -> &[u64] {
        match self {
            Self::One(m) => std::slice::from_ref(m),
            Self::Many(ms) => ms,
        }
    }
}

/// How the class_data items were found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Walk {
    /// Sequentially from the map list's class_data entry.
    Map,
    /// Through each class_def's class_data_off.
    Def,
}

/// An owner as a node of a persistent list: Python builds each merged owner as
/// a new list (`[new, old]` or `old + [new]`), and copying them here would keep
/// every intermediate list alive, quadratic in the methods sharing a bucket.
/// A node is the list of its parent chain plus `last`; a chain of one is an int.
#[derive(Debug, Clone, Copy)]
struct Node {
    /// Parent node index plus one; 0 for none.
    prev: u32,
    /// The list's first element: the method `locate` verifies against.
    first: u64,
    last: u64,
    len: u64,
}

pub struct InsnLocator {
    /// bucket (insn_off >> 4) -> index into `nodes` plus one; 0 is empty.
    /// Buckets never pass `len >> 4`: every instruction range is inside the buffer.
    table: Vec<u32>,
    nodes: Vec<Node>,
    buckets: usize,
    min_bucket: usize,
    max_bucket: usize,
    method_bounds: HashMap<u64, usize>,
    pub walk: Walk,
}

impl InsnLocator {
    /// `parse`: walk every class_data item and fill the bucket table.
    pub fn parse(dex: &Dex<'_>) -> Result<Self, AscError> {
        let buf = dex.buf;
        let mut loc = Self {
            table: vec![0; (buf.len() >> 4).saturating_add(1)],
            nodes: Vec::new(),
            buckets: 0,
            min_bucket: usize::MAX,
            max_bucket: 0,
            method_bounds: HashMap::new(),
            walk: Walk::Map,
        };
        match class_data_run(dex) {
            Some((mut pos, count)) => {
                for _ in 0..count {
                    pos = loc.class_data(buf, pos)?;
                }
            }
            None => {
                loc.walk = Walk::Def;
                let (off, size) = dex.header.classes;
                let in_range = size
                    .checked_mul(32)
                    .and_then(|len| off.checked_add(len))
                    .is_some_and(|end| end <= buf.len());
                if !in_range {
                    return Err(AscError::BadClassDefsRange);
                }
                for i in 0..size {
                    let class_data_off = i
                        .checked_mul(32)
                        .and_then(|rel| rel.checked_add(off)?.checked_add(24))
                        .and_then(|at| u32_at(buf, at))
                        .ok_or(AscError::BadClassDefsRange)?;
                    if class_data_off != 0 {
                        loc.class_data(buf, class_data_off as usize)?;
                    }
                }
            }
        }
        Ok(loc)
    }

    /// `_class_data_parse`: returns the position after the item. Unlike
    /// tinydex, fields are skipped with the unbounded length reader and there
    /// is no repeat check.
    fn class_data(&mut self, buf: &[u8], mut pos: usize) -> Result<usize, AscError> {
        let fast = |pos: &mut usize| -> Result<u64, AscError> {
            let (v, n) = read_uleb128(buf, *pos)?;
            *pos = pos.checked_add(n).ok_or(AscError::UnterminatedUleb128)?;
            Ok(v)
        };
        let static_fields = fast(&mut pos)?;
        let instance_fields = fast(&mut pos)?;
        let direct_methods = fast(&mut pos)?;
        let virtual_methods = fast(&mut pos)?;
        let skip = |pos: &mut usize| -> Result<(), AscError> {
            let n = uleb128_len(buf, *pos)?;
            *pos = pos.checked_add(n).ok_or(AscError::UnterminatedUleb128)?;
            Ok(())
        };
        // Each entry consumes at least one byte, so a count past the buffer
        // ends in "unterminated uleb128" long before the count runs out.
        for _ in 0..static_fields.saturating_add(instance_fields) {
            skip(&mut pos)?;
            skip(&mut pos)?;
        }
        for count in [direct_methods, virtual_methods] {
            let mut midx = 0u64;
            for _ in 0..count {
                let (diff, n) = read_uleb128(buf, pos)?;
                pos = pos.checked_add(n).ok_or(AscError::UnterminatedUleb128)?;
                midx = midx.saturating_add(diff);
                skip(&mut pos)?;
                let (code_off, n) = read_uleb128(buf, pos)?;
                pos = pos.checked_add(n).ok_or(AscError::UnterminatedUleb128)?;
                self.encoded_method(buf, code_off, midx)?;
            }
        }
        Ok(pos)
    }

    /// `_encoded_method_parse`.
    fn encoded_method(&mut self, buf: &[u8], code_off: u64, midx: u64) -> Result<(), AscError> {
        if code_off == 0 {
            return Ok(());
        }
        // A header past the end is struct.error in Python, mapped to this.
        let code_off = usize::try_from(code_off).map_err(|_| AscError::BadCodeItemOffset)?;
        let insns_size = code_off
            .checked_add(12)
            .and_then(|at| u32_at(buf, at))
            .ok_or(AscError::BadCodeItemOffset)? as usize;
        let insn_off = code_off
            .checked_add(16)
            .ok_or(AscError::BadCodeItemOffset)?;
        let insn_end = insns_size
            .checked_mul(2)
            .and_then(|len| insn_off.checked_add(len))
            .filter(|&end| end <= buf.len())
            .ok_or(AscError::BadCodeItemOffset)?;
        let start = insn_off >> 4;
        // insn_off >= 16, so the subtraction cannot wrap. An empty body fills
        // no bucket when insn_off is 16-aligned, and its own bucket otherwise.
        let end = insn_end.saturating_sub(1) >> 4;

        self.method_bounds.insert(midx, insn_off);
        if end < start {
            return Ok(());
        }
        // A method starting in an occupied bucket joins its owner: an int
        // `old` becomes `[new, old]`, a list gets `new` appended.
        let one = |m| Node {
            prev: 0,
            first: m,
            last: m,
            len: 1,
        };
        let id = match self.node_at(start) {
            None => self.push_node(one(midx))?,
            Some((_, old)) if old.len == 1 => {
                let head = self.push_node(one(midx))?;
                self.push_node(Node {
                    prev: head,
                    first: midx,
                    last: old.last,
                    len: 2,
                })?
            }
            Some((old_id, old)) => self.push_node(Node {
                prev: old_id,
                first: old.first,
                last: midx,
                len: old.len.saturating_add(1),
            })?,
        };
        let slots = self
            .table
            .get_mut(start..=end)
            .ok_or(AscError::BadCodeItemOffset)?;
        for slot in slots {
            if *slot == 0 {
                self.buckets = self.buckets.saturating_add(1);
            }
            *slot = id;
        }
        self.min_bucket = self.min_bucket.min(start);
        self.max_bucket = self.max_bucket.max(end);
        Ok(())
    }

    /// Appends a node; returns its index plus one.
    fn push_node(&mut self, node: Node) -> Result<u32, AscError> {
        self.nodes.push(node);
        u32::try_from(self.nodes.len()).map_err(|_| AscError::BadCodeItemOffset)
    }

    fn node(&self, id: u32) -> Option<Node> {
        self.nodes.get((id as usize).checked_sub(1)?).copied()
    }

    /// The node owning `bucket` and its id (index plus one).
    fn node_at(&self, bucket: usize) -> Option<(u32, Node)> {
        let id = *self.table.get(bucket)?;
        Some((id, self.node(id)?))
    }

    /// The owner a node stands for, as Python holds it.
    fn owner(&self, node: Node) -> Owner {
        if node.len == 1 {
            return Owner::One(node.last);
        }
        let mut mids = Vec::with_capacity(usize::try_from(node.len).unwrap_or(0));
        let mut cur = Some(node);
        while let Some(n) = cur {
            mids.push(n.last);
            cur = self.node(n.prev);
        }
        mids.reverse();
        Owner::Many(mids)
    }

    /// `[code_item_start, code_item_end)`: bucket-aligned, `(0, 0)` when empty.
    pub fn code_range(&self) -> (usize, usize) {
        if self.buckets == 0 {
            return (0, 0);
        }
        (self.min_bucket << 4, self.max_bucket.saturating_add(1) << 4)
    }

    pub fn bucket_count(&self) -> usize {
        self.buckets
    }

    /// `locate`: the owner of each hit whose instruction walk verifies, or
    /// `None`. Hits must be in ascending order: a verified hit becomes the start
    /// of the next walk in the same method.
    pub fn verify(&self, buf: &[u8], offsets: &[usize]) -> Vec<Option<Owner>> {
        let mut bounds: HashMap<u64, usize> = HashMap::new();
        offsets
            .iter()
            .map(|&off| {
                let (_, node) = self.node_at(off >> 4)?;
                let key = node.first;
                let start = bounds
                    .get(&key)
                    .or_else(|| self.method_bounds.get(&key))
                    .copied()?;
                if walk_reaches(buf, start, off) {
                    bounds.insert(key, off);
                    Some(self.owner(node))
                } else {
                    None
                }
            })
            .collect()
    }

    /// Occupied buckets and their owners, ascending, for the stage dump.
    pub fn bucket_entries(&self) -> impl Iterator<Item = (usize, Owner)> + '_ {
        self.table
            .iter()
            .enumerate()
            .filter_map(|(b, &id)| Some((b, self.owner(self.node(id)?))))
    }

    /// `method_bounds` sorted by method idx, for the stage dump.
    pub fn bounds(&self) -> Vec<(u64, usize)> {
        let mut b: Vec<(u64, usize)> = self.method_bounds.iter().map(|(&m, &o)| (m, o)).collect();
        b.sort_unstable();
        b
    }
}

/// `_build_map_bymap`'s fallback rules: the class_data run from the map list,
/// or `None` to walk class_defs.
fn class_data_run(dex: &Dex<'_>) -> Option<(usize, u32)> {
    let buf = dex.buf;
    let map_off = dex.header.map_off;
    if map_off == 0 || map_off.checked_add(4)? > buf.len() {
        return None;
    }
    let size = u32_at(buf, map_off)? as usize;
    let list = map_off.checked_add(4)?;
    if list.checked_add(size.checked_mul(12)?)? > buf.len() {
        return None;
    }
    let entry = (0..size)
        .map(|i| list.saturating_add(i.saturating_mul(12)))
        .find(|&at| u16_at(buf, at) == Some(0x2000))?;
    let count = u32_at(buf, entry.checked_add(4)?)?;
    let off = u32_at(buf, entry.checked_add(8)?)?;
    Some((off as usize, count))
}
