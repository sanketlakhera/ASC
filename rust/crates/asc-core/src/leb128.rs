use crate::error::AscError;

/// Read an unsigned LEB128 integer using fast bounds-checked decoding.
/// Reads at most 5 bytes and returns `(value, length)`.
/// Supports up to 35 bits matching Python `read_uleb128_fast`.
pub fn read_uleb128(buf: &[u8], pos: usize) -> Result<(u64, usize), AscError> {
    let b0 = *buf.get(pos).ok_or(AscError::UnterminatedUleb128)?;
    if b0 < 0x80 {
        return Ok((u64::from(b0), 1));
    }
    let mut res = u64::from(b0 & 0x7f);

    let b1 = *buf
        .get(pos.checked_add(1).ok_or(AscError::UnterminatedUleb128)?)
        .ok_or(AscError::UnterminatedUleb128)?;
    res |= u64::from(b1 & 0x7f) << 7;
    if b1 < 0x80 {
        return Ok((res, 2));
    }

    let b2 = *buf
        .get(pos.checked_add(2).ok_or(AscError::UnterminatedUleb128)?)
        .ok_or(AscError::UnterminatedUleb128)?;
    res |= u64::from(b2 & 0x7f) << 14;
    if b2 < 0x80 {
        return Ok((res, 3));
    }

    let b3 = *buf
        .get(pos.checked_add(3).ok_or(AscError::UnterminatedUleb128)?)
        .ok_or(AscError::UnterminatedUleb128)?;
    res |= u64::from(b3 & 0x7f) << 21;
    if b3 < 0x80 {
        return Ok((res, 4));
    }

    let b4 = *buf
        .get(pos.checked_add(4).ok_or(AscError::UnterminatedUleb128)?)
        .ok_or(AscError::UnterminatedUleb128)?;
    res |= u64::from(b4 & 0x7f) << 28;
    Ok((res, 5))
}

/// Compute length of a ULEB128 integer without bounding to 5 bytes.
/// Matches Python `read_uleb128_len`.
pub fn uleb128_len(buf: &[u8], pos: usize) -> Result<usize, AscError> {
    let b0 = *buf.get(pos).ok_or(AscError::UnterminatedUleb128)?;
    if b0 < 0x80 {
        return Ok(1);
    }
    let b1 = *buf
        .get(pos.checked_add(1).ok_or(AscError::UnterminatedUleb128)?)
        .ok_or(AscError::UnterminatedUleb128)?;
    if b1 < 0x80 {
        return Ok(2);
    }
    let b2 = *buf
        .get(pos.checked_add(2).ok_or(AscError::UnterminatedUleb128)?)
        .ok_or(AscError::UnterminatedUleb128)?;
    if b2 < 0x80 {
        return Ok(3);
    }
    let b3 = *buf
        .get(pos.checked_add(3).ok_or(AscError::UnterminatedUleb128)?)
        .ok_or(AscError::UnterminatedUleb128)?;
    if b3 < 0x80 {
        return Ok(4);
    }
    let b4 = *buf
        .get(pos.checked_add(4).ok_or(AscError::UnterminatedUleb128)?)
        .ok_or(AscError::UnterminatedUleb128)?;
    if b4 < 0x80 {
        return Ok(5);
    }

    let mut p = pos.checked_add(5).ok_or(AscError::UnterminatedUleb128)?;
    while *buf.get(p).ok_or(AscError::UnterminatedUleb128)? >= 0x80 {
        p = p.checked_add(1).ok_or(AscError::UnterminatedUleb128)?;
    }
    p.checked_sub(pos)
        .and_then(|diff| diff.checked_add(1))
        .ok_or(AscError::UnterminatedUleb128)
}

/// Skip over a ULEB128 value, returning the offset immediately following it.
/// Matches Python `apk_handler._skip_uleb128`.
pub fn skip_uleb128(buf: &[u8], mut off: usize) -> Result<usize, AscError> {
    while *buf.get(off).ok_or(AscError::UnterminatedUleb128)? & 0x80 != 0 {
        off = off.checked_add(1).ok_or(AscError::UnterminatedUleb128)?;
    }
    off.checked_add(1).ok_or(AscError::UnterminatedUleb128)
}

/// Read a signed LEB128 integer.
/// Matches Python `read_sleb128` behavior (sign-extending only when shift < 32).
/// Supports inputs up to 9 bytes into `i64`.
pub fn read_sleb128(buf: &[u8], pos: usize) -> Result<(i64, usize), AscError> {
    let mut result: i64 = 0;
    let mut shift: u32 = 0;
    let mut current_pos = pos;
    let mut last_byte: u8;

    loop {
        let b = *buf.get(current_pos).ok_or(AscError::UnterminatedSleb128)?;
        current_pos = current_pos
            .checked_add(1)
            .ok_or(AscError::UnterminatedSleb128)?;
        last_byte = b;

        let count = current_pos
            .checked_sub(pos)
            .ok_or(AscError::UnterminatedSleb128)?;
        if count > 9 {
            return Err(AscError::Custom("sleb128 exceeds 9 bytes".to_string()));
        }

        if shift < 64 {
            let chunk = i64::from(b & 0x7f);
            result |= chunk << shift;
        }
        shift = shift.saturating_add(7);

        if b & 0x80 == 0 {
            break;
        }
    }

    if shift < 32 && (last_byte & 0x40) != 0 {
        result |= -((1i64) << shift);
    }

    let size = current_pos
        .checked_sub(pos)
        .ok_or(AscError::UnterminatedSleb128)?;
    Ok((result, size))
}

/// Write a 32-bit unsigned integer as ULEB128 into the output buffer.
pub fn write_uleb128(mut v: u32, out: &mut Vec<u8>) {
    if v == 0 {
        out.push(0x00);
        return;
    }
    while v > 0x7f {
        let byte = ((v as u8) & 0x7f) | 0x80;
        out.push(byte);
        v >>= 7;
    }
    out.push(v as u8);
}

/// Write a 32-bit signed integer as SLEB128 into the output buffer.
pub fn write_sleb128(mut value: i32, out: &mut Vec<u8>) {
    let mut more = true;
    while more {
        let mut byte = (value & 0x7f) as u8;
        value >>= 7;
        if (value == 0 && (byte & 0x40) == 0) || (value == -1 && (byte & 0x40) != 0) {
            more = false;
        } else {
            byte |= 0x80;
        }
        out.push(byte);
    }
}
