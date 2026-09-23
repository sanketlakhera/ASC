use crate::bytes::u32_at;

pub const DEX_HEADER_MIN_SIZE: usize = 0x70;
pub const DEX041_MAGIC: &[u8; 8] = b"dex\n041\x00";

/// Returns true if the buffer starts with the DEX041 container magic.
pub fn is_dex041_container(data: &[u8]) -> bool {
    data.len() >= DEX_HEADER_MIN_SIZE && data.get(..8) == Some(DEX041_MAGIC)
}

/// Extracts logical header offsets for each logical DEX inside a DEX041 container.
/// Returns `vec![0]` if the buffer is not a DEX041 container.
pub fn dex041_logical_offsets(data: &[u8]) -> Vec<usize> {
    if !is_dex041_container(data) {
        return vec![0];
    }
    let mut offsets = Vec::new();
    let mut off = 0;

    while let Some(rest) = data
        .get(off..)
        .filter(|r| r.len() >= DEX_HEADER_MIN_SIZE && r.starts_with(DEX041_MAGIC))
    {
        let Some(file_size) = u32_at(rest, 0x20) else {
            break;
        };
        let file_size = file_size as usize;
        if file_size < DEX_HEADER_MIN_SIZE || file_size > rest.len() {
            break;
        }
        offsets.push(off);
        // Bounded by `data.len()` by the check above.
        off = off.saturating_add(file_size);
    }

    if offsets.is_empty() { vec![0] } else { offsets }
}

/// Normalizes a logical DEX from a DEX041 container by replacing the first `header_size`
/// bytes with the header at `header_off`.
pub fn normalize_dex041_logical(data: &[u8], header_off: usize) -> Vec<u8> {
    if header_off == 0 {
        return data.to_vec();
    }
    let logical = data.get(header_off..).unwrap_or_default();
    let header_size = match u32_at(logical, 0x24) {
        Some(sz) if sz as usize >= DEX_HEADER_MIN_SIZE && sz as usize <= logical.len() => {
            sz as usize
        }
        _ => DEX_HEADER_MIN_SIZE,
    };

    let mut out = data.to_vec();
    // `dex041_logical_offsets` only yields offsets with a full header behind them;
    // for any other offset the buffer is returned unchanged.
    if let (Some(dst), Some(src)) = (out.get_mut(..header_size), logical.get(..header_size)) {
        dst.copy_from_slice(src);
    }
    out
}

/// Iterates logical DEX buffers, returning (logical_name, buffer).
/// For standard DEX, returns `[(name, Cow::Borrowed(data))]`.
/// For DEX041 multi-DEX, returns one entry per sub-DEX.
pub fn iter_logical_dex_buffers<'a>(
    name: &'a str,
    data: &'a [u8],
) -> Vec<(String, std::borrow::Cow<'a, [u8]>)> {
    let offsets = dex041_logical_offsets(data);
    if offsets.len() <= 1 {
        return vec![(name.to_string(), std::borrow::Cow::Borrowed(data))];
    }

    offsets
        .into_iter()
        .zip(1..)
        .map(|(header_off, n)| {
            let logical_name = format!("{name}!classes{n}.dex");
            let normalized = normalize_dex041_logical(data, header_off);
            (logical_name, std::borrow::Cow::Owned(normalized))
        })
        .collect()
}
