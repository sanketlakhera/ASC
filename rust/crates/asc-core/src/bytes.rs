//! Bounds-checked byte reads shared by the ZIP and DEX parsers.
//!
//! Every helper returns `None` instead of panicking when the read would run past
//! the end of the buffer; callers map that to the error their format dictates.

/// The `len` bytes starting at `off`.
pub(crate) fn record(buf: &[u8], off: usize, len: usize) -> Option<&[u8]> {
    buf.get(off..)?.get(..len)
}

/// Little-endian `u16` at `off`.
pub(crate) fn u16_at(buf: &[u8], off: usize) -> Option<u16> {
    array_at(buf, off).map(u16::from_le_bytes)
}

/// Little-endian `u32` at `off`.
pub(crate) fn u32_at(buf: &[u8], off: usize) -> Option<u32> {
    array_at(buf, off).map(u32::from_le_bytes)
}

/// The bytes before the first NUL, or `None` if `buf` has no NUL.
pub(crate) fn until_nul(buf: &[u8]) -> Option<&[u8]> {
    let len = buf.iter().position(|&b| b == 0)?;
    buf.get(..len)
}

fn array_at<const N: usize>(buf: &[u8], off: usize) -> Option<[u8; N]> {
    buf.get(off..)?.first_chunk().copied()
}
