//! `InsnLocator.INSN_VERIFY` as a walk.
//!
//! Python verifies a hit with `INSN_VERIFY.fullmatch(buf, start, end)`, where
//! `INSN_VERIFY` is `(?>(?:[ops1].{1}|[ops2].{3}|...|[ops5].{9})*)` under DOTALL
//! (the atomic group is dropped on Python 3.10). The opcode sets are disjoint
//! and every alternative has a fixed length, so at each position at most one
//! alternative applies: the regex is a deterministic walk, and the atomic and
//! plain forms accept the same ranges (`vectors/insn_verify.json` pins both).

use crate::opcode::OPCODES;
use std::sync::LazyLock;

/// Instruction length in bytes by opcode; 0 for an undefined opcode.
static INSN_BYTES: LazyLock<[u8; 256]> = LazyLock::new(|| {
    let mut table = [0u8; 256];
    for (slot, op) in table.iter_mut().zip(OPCODES.iter()) {
        *slot = op.as_ref().map_or(0, |o| o.len.saturating_mul(2));
    }
    table
});

/// Whether walking instructions from `start` lands exactly on `end`: no
/// undefined opcode on the way and no instruction crossing `end`.
///
/// Both bounds are clamped to the buffer as `fullmatch` clamps `pos` and
/// `endpos`; `start > end` never matches, `start == end` always does.
pub fn walk_reaches(buf: &[u8], start: usize, end: usize) -> bool {
    let end = end.min(buf.len());
    let mut p = start.min(buf.len());
    if p > end {
        return false;
    }
    let lengths = &*INSN_BYTES;
    while p < end {
        let len = buf
            .get(p)
            .and_then(|&op| lengths.get(usize::from(op)))
            .copied()
            .unwrap_or(0);
        if len == 0 {
            return false;
        }
        let next = p.saturating_add(usize::from(len));
        if next > end {
            return false;
        }
        p = next;
    }
    true
}
