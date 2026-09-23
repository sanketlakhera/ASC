use serde::{Deserialize, Serialize};
use std::fmt;
use std::ops::Deref;

/// A DEX string holding UTF-16 code units (where lone surrogates are preserved).
/// Serializes to JSON as an array of 16-bit integers, matching Python conformance dumps.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct DexStr(pub Vec<u16>);

impl DexStr {
    pub fn new(units: Vec<u16>) -> Self {
        Self(units)
    }

    pub fn as_slice(&self) -> &[u16] {
        &self.0
    }

    /// Lossy conversion to UTF-8 String (lone surrogates replaced with U+FFFD).
    /// Used for logging or human-readable display only.
    pub fn to_string_lossy(&self) -> String {
        String::from_utf16_lossy(&self.0)
    }

    pub fn utf16_len(&self) -> usize {
        self.0.len()
    }
}

impl Deref for DexStr {
    type Target = [u16];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl fmt::Display for DexStr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_string_lossy())
    }
}

/// Decode a Modified UTF-8 payload (without NUL terminator) into `DexStr`.
///
/// Implements Python `droidasc.asc_core.utils.mutf8.decode_mutf8`:
/// 1. Fast path for ASCII.
/// 2. Primary path replacing `C0 80` with `00` and decoding CESU-8/UTF-8 with surrogate pass.
/// 3. Fallback on any decode error to UTF-8 maximal subpart lossy replacement.
pub fn decode_mutf8(payload: &[u8]) -> DexStr {
    if payload.iter().all(|&b| b < 0x80) {
        let units: Vec<u16> = payload.iter().map(|&b| u16::from(b)).collect();
        return DexStr(units);
    }

    // Try primary decode path
    if let Some(units) = try_decode_primary(payload) {
        return DexStr(units);
    }

    // Fallback: decode raw payload as UTF-8 with standard maximal subpart replacement
    let s = String::from_utf8_lossy(payload);
    let mut units = Vec::with_capacity(s.len());
    for c in s.chars() {
        let mut buf = [0u16; 2];
        units.extend_from_slice(c.encode_utf16(&mut buf));
    }
    DexStr(units)
}

fn try_decode_primary(payload: &[u8]) -> Option<Vec<u16>> {
    let mut units = Vec::with_capacity(payload.len());
    let mut i = 0;
    let len = payload.len();

    while i < len {
        let b0 = *payload.get(i)?;

        // Check C0 80 (MUTF-8 encoded NUL)
        if b0 == 0xc0 {
            let b1 = *payload.get(i.checked_add(1)?)?;
            if b1 == 0x80 {
                units.push(0x0000);
                i = i.checked_add(2)?;
                continue;
            }
            return None;
        }

        if b0 < 0x80 {
            units.push(u16::from(b0));
            i = i.checked_add(1)?;
        } else if (0xc2..=0xdf).contains(&b0) {
            let b1 = *payload.get(i.checked_add(1)?)?;
            if !(0x80..=0xbf).contains(&b1) {
                return None;
            }
            let val = (u16::from(b0 & 0x1f) << 6) | u16::from(b1 & 0x3f);
            units.push(val);
            i = i.checked_add(2)?;
        } else if (0xe0..=0xef).contains(&b0) {
            let b1 = *payload.get(i.checked_add(1)?)?;
            let b2 = *payload.get(i.checked_add(2)?)?;
            if !(0x80..=0xbf).contains(&b2) {
                return None;
            }
            // Check overlong and surrogate bounds
            if b0 == 0xe0 && !(0xa0..=0xbf).contains(&b1) {
                return None;
            }
            if b0 != 0xe0 && !(0x80..=0xbf).contains(&b1) {
                return None;
            }
            let val =
                (u16::from(b0 & 0x0f) << 12) | (u16::from(b1 & 0x3f) << 6) | u16::from(b2 & 0x3f);
            units.push(val);
            i = i.checked_add(3)?;
        } else if (0xf0..=0xf4).contains(&b0) {
            // 4-byte standard UTF-8 sequence
            let b1 = *payload.get(i.checked_add(1)?)?;
            let b2 = *payload.get(i.checked_add(2)?)?;
            let b3 = *payload.get(i.checked_add(3)?)?;
            if !(0x80..=0xbf).contains(&b2) || !(0x80..=0xbf).contains(&b3) {
                return None;
            }
            if b0 == 0xf0 && !(0x90..=0xbf).contains(&b1) {
                return None;
            }
            if b0 == 0xf4 && !(0x80..=0x8f).contains(&b1) {
                return None;
            }
            if !(0xf0..=0xf4).contains(&b0)
                || (b0 > 0xf0 && b0 < 0xf4 && !(0x80..=0xbf).contains(&b1))
            {
                return None;
            }

            let cp = (u32::from(b0 & 0x07) << 18)
                | (u32::from(b1 & 0x3f) << 12)
                | (u32::from(b2 & 0x3f) << 6)
                | u32::from(b3 & 0x3f);

            if cp > 0x10ffff {
                return None;
            }
            let sub = cp.checked_sub(0x10000)?;
            let high = 0xd800 | ((sub >> 10) as u16);
            let low = 0xdc00 | ((sub & 0x3ff) as u16);
            units.push(high);
            units.push(low);
            i = i.checked_add(4)?;
        } else {
            return None;
        }
    }

    Some(units)
}

/// Encode UTF-16 units into MUTF-8 bytes (without terminator).
/// Matches Python `droidasc.asc_core.utils.mutf8.encode_mutf8`.
pub fn encode_mutf8(units: &[u16]) -> Vec<u8> {
    let mut out = Vec::with_capacity(units.len().saturating_mul(3));
    for &unit in units {
        if 0 < unit && unit < 0x80 {
            out.push(unit as u8);
        } else if unit < 0x800 {
            out.push(0xc0 | ((unit >> 6) as u8));
            out.push(0x80 | ((unit & 0x3f) as u8));
        } else {
            out.push(0xe0 | ((unit >> 12) as u8));
            out.push(0x80 | (((unit >> 6) & 0x3f) as u8));
            out.push(0x80 | ((unit & 0x3f) as u8));
        }
    }
    out
}

/// Return length of string in UTF-16 code units.
pub fn utf16_len(units: &[u16]) -> usize {
    units.len()
}
