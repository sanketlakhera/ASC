use crate::error::AscError;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Header {
    pub strings: (usize, usize),    // (off, size)
    pub types: (usize, usize),      // (off, size)
    pub prototypes: (usize, usize), // (off, size)
    pub fields: (usize, usize),     // (off, size)
    pub methods: (usize, usize),    // (off, size)
    pub classes: (usize, usize),    // (off, size)
    pub map_off: usize,
}

impl Header {
    pub fn parse(buf: &[u8]) -> Result<Self, AscError> {
        if buf.len() < 0x70 || buf.get(..3) != Some(b"dex") {
            return Err(AscError::BadDexMagicOrHeaderSize);
        }

        let read_u32 = |off: usize| -> usize {
            u32::from_le_bytes(buf[off..off + 4].try_into().unwrap()) as usize
        };

        Ok(Self {
            strings: (read_u32(0x3C), read_u32(0x38)),
            types: (read_u32(0x44), read_u32(0x40)),
            prototypes: (read_u32(0x4C), read_u32(0x48)),
            fields: (read_u32(0x54), read_u32(0x50)),
            methods: (read_u32(0x5C), read_u32(0x58)),
            classes: (read_u32(0x64), read_u32(0x60)),
            map_off: read_u32(0x34),
        })
    }
}
