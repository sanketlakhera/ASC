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
    let data_len = data.len();

    while off + DEX_HEADER_MIN_SIZE <= data_len && data.get(off..off + 8) == Some(DEX041_MAGIC) {
        let file_size =
            u32::from_le_bytes(data[off + 0x20..off + 0x24].try_into().unwrap()) as usize;
        if file_size < DEX_HEADER_MIN_SIZE || off + file_size > data_len {
            break;
        }
        offsets.push(off);
        off += file_size;
    }

    if offsets.is_empty() { vec![0] } else { offsets }
}

/// Normalizes a logical DEX from a DEX041 container by replacing the first `header_size`
/// bytes with the header at `header_off`.
pub fn normalize_dex041_logical(data: &[u8], header_off: usize) -> Vec<u8> {
    if header_off == 0 {
        return data.to_vec();
    }
    let header_size = if header_off + 0x28 <= data.len() {
        let sz = u32::from_le_bytes(
            data[header_off + 0x24..header_off + 0x28]
                .try_into()
                .unwrap(),
        ) as usize;
        if sz < DEX_HEADER_MIN_SIZE || header_off + sz > data.len() {
            DEX_HEADER_MIN_SIZE
        } else {
            sz
        }
    } else {
        DEX_HEADER_MIN_SIZE
    };

    let mut out = data.to_vec();
    out[..header_size].copy_from_slice(&data[header_off..header_off + header_size]);
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
        .enumerate()
        .map(|(idx, header_off)| {
            let logical_name = format!("{name}!classes{}.dex", idx + 1);
            let normalized = normalize_dex041_logical(data, header_off);
            (logical_name, std::borrow::Cow::Owned(normalized))
        })
        .collect()
}
