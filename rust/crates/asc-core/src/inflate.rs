use crate::bytes::{record, u16_at};
use crate::error::AscError;
use crate::zip::{DexEntry, LH_SIG};
use flate2::{Decompress, FlushDecompress, Status};
use std::sync::atomic::{AtomicBool, Ordering};

const DEFLATE_CHUNK: usize = 1 << 19; // 512 KiB
/// Upper bound of raw deflate expansion (258-byte match per ~2 bits of input).
const DEFLATE_MAX_RATIO: usize = 1032;

/// Inflates a DEX entry from an APK / ZIP buffer.
///
/// Supports method 0 (stored) and method 8 (raw deflate, wbits = -15).
/// Respects optional cancellation token checked every 512 KiB.
pub fn inflate_entry(
    data: &[u8],
    entry: &DexEntry,
    cancel: Option<&AtomicBool>,
) -> Result<Option<Vec<u8>>, AscError> {
    let lh_off = entry.local_header_off as usize;
    if lh_off + 30 > data.len() || data.get(lh_off..lh_off + 4) != Some(&LH_SIG) {
        return Err(AscError::BadLocalHeaderSignature);
    }

    let name_len = u16_at(data, lh_off + 26).ok_or(AscError::BadLocalHeaderSignature)? as usize;
    let extra_len = u16_at(data, lh_off + 28).ok_or(AscError::BadLocalHeaderSignature)? as usize;

    let data_off = lh_off + 30 + name_len + extra_len;
    let comp_size = entry.comp_size as usize;
    let comp_slice = record(data, data_off, comp_size).ok_or(AscError::BadCompressedDataRange)?;

    let decompressed = match entry.method {
        0 => {
            if cancel.is_some_and(|c| c.load(Ordering::Relaxed)) {
                return Ok(None);
            }
            comp_slice.to_vec()
        }
        8 => match inflate_deflate(comp_slice, entry.uncomp_size as usize, &entry.name, cancel)? {
            Some(d) => d,
            None => return Ok(None),
        },
        m => return Err(AscError::UnsupportedCompressionMethod(m)),
    };

    if entry.uncomp_size != 0 && decompressed.len() != entry.uncomp_size as usize {
        return Err(AscError::SizeMismatch {
            expected: entry.uncomp_size,
            got: decompressed.len(),
        });
    }

    Ok(Some(decompressed))
}

fn inflate_deflate(
    comp_slice: &[u8],
    capacity_hint: usize,
    entry_name: &str,
    cancel: Option<&AtomicBool>,
) -> Result<Option<Vec<u8>>, AscError> {
    let mut decompressor = Decompress::new(false);
    // The hint comes from the central directory and is attacker-controlled; never
    // reserve more than the stream could possibly produce.
    let max_output = comp_slice.len().saturating_mul(DEFLATE_MAX_RATIO);
    let mut out = Vec::with_capacity(if capacity_hint > 0 {
        capacity_hint.min(max_output)
    } else {
        comp_slice.len().saturating_mul(2)
    });
    let mut temp_buf = [0u8; 64 * 1024];

    let corrupt = || AscError::CorruptDeflateStream(entry_name.to_string());

    for mut chunk in comp_slice.chunks(DEFLATE_CHUNK) {
        if cancel.is_some_and(|c| c.load(Ordering::Relaxed)) {
            return Ok(None);
        }

        while !chunk.is_empty() {
            let before_in = decompressor.total_in();
            let before_out = decompressor.total_out();

            let status = decompressor
                .decompress(chunk, &mut temp_buf, FlushDecompress::None)
                .map_err(|_| AscError::CorruptDeflateStream(entry_name.to_string()))?;

            let consumed = (decompressor.total_in() - before_in) as usize;
            let produced = (decompressor.total_out() - before_out) as usize;

            // flate2 never reports more than it was given, so these cannot fail.
            chunk = chunk.get(consumed..).ok_or_else(corrupt)?;
            out.extend_from_slice(temp_buf.get(..produced).ok_or_else(corrupt)?);

            if status == Status::StreamEnd {
                if cancel.is_some_and(|c| c.load(Ordering::Relaxed)) {
                    return Ok(None);
                }
                return Ok(Some(out));
            }

            if consumed == 0 && produced == 0 {
                return Err(AscError::CorruptDeflateStream(entry_name.to_string()));
            }
        }
    }

    let mut finished = false;
    loop {
        let before_out = decompressor.total_out();
        let status = decompressor
            .decompress(&[], &mut temp_buf, FlushDecompress::Finish)
            .map_err(|_| AscError::CorruptDeflateStream(entry_name.to_string()))?;
        let produced = (decompressor.total_out() - before_out) as usize;
        out.extend_from_slice(temp_buf.get(..produced).ok_or_else(corrupt)?);

        if status == Status::StreamEnd {
            finished = true;
            break;
        }
        if produced == 0 {
            break;
        }
    }

    if !finished {
        return Err(AscError::CorruptDeflateStream(entry_name.to_string()));
    }

    if cancel.is_some_and(|c| c.load(Ordering::Relaxed)) {
        return Ok(None);
    }

    Ok(Some(out))
}
